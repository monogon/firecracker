// Copyright The Monogon Project Authors.
// SPDX-License-Identifier: Apache-2.0

//! Bounded, synchronous NBD over a private Unix socket. The existing virtio
//! frontend owns queues and dirty tracking; no guest addresses reach the server.
//! No automatic reconnect/retry: a lost write reply has ambiguous completion.
//!
//! The server sends the oldstyle greeting and then serves transmission
//! requests, as E2B's NBD dispatcher does for the kernel client.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::vstate::memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

const MAX_IO: usize = 1024 * 1024;
/// E2B's export serves 4 KiB blocks and, like its kernel client, needs
/// block-aligned requests. The guest sees this as the logical block size.
pub const BLOCK_SIZE: u32 = 4096;
const REQUEST_MAGIC: u32 = 0x25609513;
const REPLY_MAGIC: u32 = 0x67446698;
const OLDSTYLE_MAGIC: u64 = 0x00420281861253;
// Transmission flags.
const FLAG_HAS_FLAGS: u16 = 1 << 0;
const FLAG_READ_ONLY: u16 = 1 << 1;
const FLAG_SEND_FLUSH: u16 = 1 << 2;
const FLAG_SEND_TRIM: u16 = 1 << 5;
const FLAG_SEND_WRITE_ZEROES: u16 = 1 << 6;

#[derive(Debug)]
pub struct NbdEngine {
    // File uses read/write syscalls already allowed by the VMM seccomp profile.
    socket: File,
    pub size: u64,
    handle: u64,
    failed: bool,
    read_only: bool,
    send_flush: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl NbdEngine {
    pub fn connect(path: &str, read_only: bool) -> io::Result<Self> {
        let mut socket = UnixStream::connect(path)?;
        socket.set_read_timeout(Some(Duration::from_secs(90)))?;
        socket.set_write_timeout(Some(Duration::from_secs(90)))?;
        // NBDMAGIC, oldstyle magic, size, 32-bit flags, 124 bytes of padding.
        let mut greeting = [0; 152];
        socket.read_exact(&mut greeting)?;
        if &greeting[..8] != b"NBDMAGIC"
            || u64::from_be_bytes(greeting[8..16].try_into().unwrap()) != OLDSTYLE_MAGIC
        {
            return Err(invalid("NBD requires the oldstyle greeting"));
        }
        let size = u64::from_be_bytes(greeting[16..24].try_into().unwrap());
        // Transmission flags are the low 16 bits of the 32-bit flags field.
        let flags = u16::from_be_bytes(greeting[26..28].try_into().unwrap());
        let required = FLAG_HAS_FLAGS | FLAG_SEND_TRIM | FLAG_SEND_WRITE_ZEROES;
        // Never accept a writable drive backed by a read-only export. Reject
        // unaligned sizes.
        if flags & required != required
            || (!read_only && flags & FLAG_READ_ONLY != 0)
            || size == 0
            || !size.is_multiple_of(u64::from(BLOCK_SIZE))
        {
            return Err(invalid(
                "NBD export lacks required capabilities or has invalid size",
            ));
        }
        Ok(Self {
            socket: File::from(OwnedFd::from(socket)),
            size,
            handle: 0,
            failed: false,
            read_only,
            send_flush: flags & FLAG_SEND_FLUSH != 0,
        })
    }

    fn range(&self, offset: u64, count: u64) -> io::Result<()> {
        if offset.checked_add(count).is_none_or(|end| end > self.size) {
            return Err(invalid("NBD request outside export"));
        }
        if !offset.is_multiple_of(u64::from(BLOCK_SIZE))
            || !count.is_multiple_of(u64::from(BLOCK_SIZE))
        {
            return Err(invalid("NBD request not block-aligned"));
        }
        Ok(())
    }

    fn command(
        &mut self,
        command: u16,
        flags: u16,
        offset: u64,
        count: u32,
        data: &mut [u8],
    ) -> io::Result<()> {
        if self.failed {
            return Err(invalid("NBD connection failed; refusing retries"));
        }
        self.handle = self.handle.wrapping_add(1);
        let result = (|| {
            let mut header = [0; 28];
            header[..4].copy_from_slice(&REQUEST_MAGIC.to_be_bytes());
            header[4..6].copy_from_slice(&flags.to_be_bytes());
            header[6..8].copy_from_slice(&command.to_be_bytes());
            header[8..16].copy_from_slice(&self.handle.to_be_bytes());
            header[16..24].copy_from_slice(&offset.to_be_bytes());
            header[24..28].copy_from_slice(&count.to_be_bytes());
            self.socket.write_all(&header)?;
            if command == 1 {
                self.socket.write_all(data)?;
            }
            let mut reply = [0; 16];
            self.socket.read_exact(&mut reply)?;
            if u32::from_be_bytes(reply[..4].try_into().unwrap()) != REPLY_MAGIC
                || u64::from_be_bytes(reply[8..].try_into().unwrap()) != self.handle
            {
                return Err(invalid("NBD reply magic/handle mismatch"));
            }
            let errno = u32::from_be_bytes(reply[4..8].try_into().unwrap());
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(
                    i32::try_from(errno).unwrap_or(libc::EIO),
                ));
            }
            if command == 0 {
                self.socket.read_exact(data)?;
            }
            Ok(())
        })();
        // Even server errors fail closed. Never snapshot after any failed I/O.
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn transfer(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> io::Result<u32> {
        self.range(offset, u64::from(count))?;
        if write && self.read_only {
            return Err(io::Error::from_raw_os_error(libc::EROFS));
        }
        // Validate the whole descriptor before the first disk operation.
        mem.get_slice(addr, count as usize)
            .map_err(io::Error::other)?;
        let mut buffer = vec![0; (count as usize).min(MAX_IO)];
        let mut done = 0;
        while done < count as usize {
            let len = (count as usize - done).min(MAX_IO);
            let guest = GuestAddress(addr.0 + done as u64);
            if write {
                mem.read_slice(&mut buffer[..len], guest)
                    .map_err(io::Error::other)?;
            }
            self.command(
                u16::from(write),
                0,
                offset + done as u64,
                len as u32,
                &mut buffer[..len],
            )?;
            // Bytes::write_slice marks dirty pages, including UFFD-backed RAM.
            if !write {
                mem.write_slice(&buffer[..len], guest)
                    .map_err(io::Error::other)?;
            }
            done += len;
        }
        Ok(count)
    }

    /// Without SEND_FLUSH the server has no volatile cache: every request
    /// completed before its reply, so there is nothing to flush. A failed
    /// connection still fails, which keeps it from being snapshotted.
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.send_flush {
            if self.failed {
                return Err(invalid("NBD connection failed; refusing retries"));
            }
            return Ok(());
        }
        self.command(3, 0, 0, 0, &mut [])
    }

    pub fn zero(&mut self, offset: u64, len: u64, discard: bool, unmap: bool) -> io::Result<()> {
        self.range(offset, len)?;
        if self.read_only {
            return Err(io::Error::from_raw_os_error(libc::EROFS));
        }
        let mut done = 0;
        while done < len {
            let count = (len - done).min(MAX_IO as u64) as u32;
            self.command(
                if discard { 4 } else { 6 },
                if !discard && !unmap { 2 } else { 0 },
                offset + done,
                count,
                &mut [],
            )?;
            done += u64::from(count);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::block::persist::BlockConstructorArgs;
    use crate::devices::virtio::block::virtio::device::{
        FileEngineType, VirtioBlock, VirtioBlockConfig,
    };
    use crate::devices::virtio::block::virtio::request::RequestHeader;
    use crate::devices::virtio::block::virtio::test_utils::RequestDescriptorChain;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::generated::virtio_blk::{VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_T_IN};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::snapshot::Persist;
    use crate::test_utils::single_region_mem;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use vm_memory::{GuestMemoryRegion, bitmap::Bitmap};

    fn server(
        path: &std::path::Path,
        connections: usize,
        bad_reply: bool,
    ) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();
        let disk = Arc::new(Mutex::new(vec![0u8; 4 * MAX_IO]));
        thread::spawn(move || {
            for _ in 0..connections {
                let (mut c, _) = listener.accept().unwrap();
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                c.write_all(b"NBDMAGIC").unwrap();
                c.write_all(&OLDSTYLE_MAGIC.to_be_bytes()).unwrap();
                c.write_all(&(4 * MAX_IO as u64).to_be_bytes()).unwrap();
                let flags = FLAG_HAS_FLAGS | FLAG_SEND_TRIM | FLAG_SEND_WRITE_ZEROES;
                c.write_all(&u32::from(flags).to_be_bytes()).unwrap();
                c.write_all(&[0; 124]).unwrap();
                loop {
                    let mut request = [0; 28];
                    if c.read_exact(&mut request).is_err() {
                        break;
                    }
                    assert_eq!(
                        u32::from_be_bytes(request[..4].try_into().unwrap()),
                        REQUEST_MAGIC
                    );
                    let command = u16::from_be_bytes(request[6..8].try_into().unwrap());
                    assert_ne!(command, 3, "FLUSH sent without SEND_FLUSH");
                    let offset = u64::from_be_bytes(request[16..24].try_into().unwrap()) as usize;
                    let count = u32::from_be_bytes(request[24..].try_into().unwrap()) as usize;
                    assert!(count <= MAX_IO);
                    let mut data = disk.lock().unwrap();
                    if command == 1 {
                        c.read_exact(&mut data[offset..offset + count]).unwrap();
                    }
                    if command == 4 || command == 6 {
                        data[offset..offset + count].fill(0);
                    }
                    c.write_all(&REPLY_MAGIC.to_be_bytes()).unwrap();
                    c.write_all(&0u32.to_be_bytes()).unwrap();
                    let mut handle = request[8..16].to_vec();
                    if bad_reply {
                        handle[0] ^= 1;
                    }
                    c.write_all(&handle).unwrap();
                    if command == 0 && !bad_reply {
                        c.write_all(&data[offset..offset + count]).unwrap();
                    }
                }
            }
        })
    }

    #[test]
    fn test_nbd_roundtrip_dirty_tracking_and_bounds() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("nbd.sock");
        let server = server(&path, 1, false);
        let mut engine = NbdEngine::connect(path.to_str().unwrap(), false).unwrap();
        let mem = single_region_mem(3 * MAX_IO);
        let count = MAX_IO as u32 + 4096;
        let data = vec![0x55; count as usize];
        mem.write_slice(&data, GuestAddress(0)).unwrap();
        engine
            .transfer(true, 4096, &mem, GuestAddress(0), count)
            .unwrap();
        let output = GuestMemoryMmap::from_regions(
            crate::vstate::memory::anonymous(
                [(GuestAddress(0), 3 * MAX_IO)].into_iter(),
                true,
                crate::vmm_config::machine_config::HugePageConfig::None,
            )
            .unwrap()
            .into_iter()
            .map(|r| {
                use crate::vstate::memory::GuestRegionMmapExt;
                GuestRegionMmapExt::dram_from_mmap_region(r, 0)
            })
            .collect(),
        )
        .unwrap();
        engine
            .transfer(false, 4096, &output, GuestAddress(0), count)
            .unwrap();
        let mut got = vec![0; count as usize];
        output.read_slice(&mut got, GuestAddress(0)).unwrap();
        assert_eq!(got, data);
        assert!(
            output
                .find_region(GuestAddress(0))
                .unwrap()
                .bitmap()
                .dirty_at(0)
        );
        engine.zero(4096, 4096, false, false).unwrap();
        engine
            .transfer(false, 4096, &output, GuestAddress(0), 4096)
            .unwrap();
        output
            .read_slice(&mut got[..4096], GuestAddress(0))
            .unwrap();
        assert!(got[..4096].iter().all(|b| *b == 0));
        // The export needs block-aligned requests; they never reach it.
        assert!(
            engine
                .transfer(false, 512, &output, GuestAddress(0), 4096)
                .is_err()
        );
        assert!(
            engine
                .transfer(true, engine.size, &mem, GuestAddress(0), 4096)
                .is_err()
        );
        assert!(
            engine
                .transfer(true, 0, &mem, GuestAddress(3 * MAX_IO as u64), 4096)
                .is_err()
        );
        engine.flush().unwrap();
        drop(engine);
        server.join().unwrap();
    }

    #[test]
    fn test_nbd_protocol_failure_is_sticky() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("nbd.sock");
        let server = server(&path, 1, true);
        let mut engine = NbdEngine::connect(path.to_str().unwrap(), false).unwrap();
        let mem = single_region_mem(MAX_IO);
        assert!(
            engine
                .transfer(false, 0, &mem, GuestAddress(0), 4096)
                .is_err()
        );
        assert!(
            engine
                .transfer(false, 0, &mem, GuestAddress(0), 4096)
                .is_err()
        );
        // Without SEND_FLUSH, flush stays local but still refuses after a failure.
        assert!(engine.flush().is_err());
        drop(engine);
        server.join().unwrap();
    }

    #[test]
    fn test_nbd_snapshot_reconnect_preserves_virtqueue_state() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("nbd.sock");
        let server = server(&path, 2, false);
        let mut block = VirtioBlock::new(VirtioBlockConfig {
            drive_id: "rootfs".into(),
            path_on_host: path.to_str().unwrap().into(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            cache_type: CacheType::Writeback,
            rate_limiter: None,
            file_engine_type: FileEngineType::Async,
        })
        .unwrap();
        // The guest uses the export's block size, so it only sends aligned I/O.
        assert_ne!(block.avail_features() & (1u64 << VIRTIO_BLK_F_BLK_SIZE), 0);
        assert_eq!({ block.config_space.blk_size }, BLOCK_SIZE);
        let guest_mem = default_mem();
        let vq = VirtQueue::new(
            GuestAddress(0x4000),
            &guest_mem,
            crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE,
        );
        let chain = RequestDescriptorChain::new(&vq);
        chain.set_header(RequestHeader::new(VIRTIO_BLK_T_IN, 0));
        block.queues[0] = vq.create_queue();
        block
            .activate(guest_mem.clone(), default_interrupt())
            .unwrap();
        block.process_queue(0).unwrap();
        assert_eq!(vq.used.idx.get(), 1);
        block.prepare_save();
        let state = block.save();
        // Snapshot state contains the reopenable path and existing Sync tag, no
        // live socket or new bincode variant. The socket selects the transport.
        let encoded = bitcode::serialize(&state).unwrap();
        let state: crate::devices::virtio::block::virtio::persist::VirtioBlockState =
            bitcode::deserialize(&encoded).unwrap();
        let features = block.avail_features();
        let queues = block.queues().to_vec();
        drop(block); // prepare_save/Drop drain and flush precede socket release
        let mut restored = VirtioBlock::restore(
            BlockConstructorArgs {
                mem: guest_mem.clone(),
            },
            &state,
        )
        .unwrap();
        restored
            .activate(guest_mem.clone(), default_interrupt())
            .unwrap();
        assert_eq!(restored.avail_features(), features);
        assert_eq!({ restored.config_space.blk_size }, BLOCK_SIZE);
        assert_eq!(restored.queues(), &queues);
        assert!(matches!(
            restored.disk.file_engine,
            super::super::FileEngine::Nbd(_)
        ));
        drop(restored);
        server.join().unwrap();
    }
    #[test]
    #[ignore = "requires the E2B Unix export integration test"]
    fn test_nbd_external_export() {
        let path = std::env::var("E2B_NBD_TEST_SOCKET").expect("E2B export socket");
        let mut engine = NbdEngine::connect(&path, false).unwrap();
        let mem = single_region_mem(3 * MAX_IO);
        let count = MAX_IO as u32 + 4096;
        let data = vec![0x42; count as usize];
        mem.write_slice(&data, GuestAddress(0)).unwrap();
        engine
            .transfer(true, 4096, &mem, GuestAddress(0), count)
            .unwrap();
        engine.flush().unwrap();
        engine
            .transfer(false, 4096, &mem, GuestAddress(MAX_IO as u64 + 8192), count)
            .unwrap();
        let mut got = vec![0; count as usize];
        mem.read_slice(&mut got, GuestAddress(MAX_IO as u64 + 8192))
            .unwrap();
        assert_eq!(got, data);
        engine.zero(4096, 4096, false, false).unwrap(); // write-zeroes with NO_HOLE
        engine.zero(8192, 4096, true, true).unwrap(); // trim
        engine.flush().unwrap();
        engine
            .transfer(false, 0, &mem, GuestAddress(0), 16384)
            .unwrap();
        let mut got = vec![0; 16384];
        mem.read_slice(&mut got, GuestAddress(0)).unwrap();
        assert!(got[..12288].iter().all(|b| *b == 0));
        assert!(got[12288..].iter().all(|b| *b == 0x42));
    }
}
