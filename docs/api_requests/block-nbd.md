# Unix-socket NBD block backend

The NBD I/O engine runs beneath Firecracker's existing virtio-blk frontend.
It is intended for E2B's lazy layered rootfs/CoW export;
no kernel NBD module, device, ioctl or netlink connection is involved.

Configure a regular virtio drive with `path_on_host` pointing to a private
pathname Unix socket and `cache_type: "Writeback"`. The socket file type selects
NBD, even when a restored configuration carries an older `Async` engine tag.
The reported/persisted I/O engine is `Sync`. Regular files and block devices
retain their existing engines. A typical drive request is:

```json
{
  "drive_id": "rootfs",
  "path_on_host": "/sandbox/rootfs.ext4",
  "is_root_device": true,
  "is_read_only": false,
  "cache_type": "Writeback",
  "io_engine": "Sync"
}
```

The path may be a symlink, as used by E2B. It must resolve to the export socket
inside the VMM's mount namespace. Use a private directory owned by the worker;
this backend provides no network transport, TLS or export authentication.

The server sends the oldstyle greeting (size and transmission flags) and then
serves transmission requests, as E2B's NBD dispatcher does for the kernel's NBD
client. The export must advertise HAS_FLAGS, TRIM and WRITE_ZEROES, with a
size that is a multiple of 4 KiB. A writable drive cannot use a read-only
export. The export serves 4 KiB blocks and needs block-aligned requests, so the
drive advertises a 4 KiB logical block size (VIRTIO_BLK_F_BLK_SIZE) and the
guest only issues aligned I/O; unaligned requests are rejected.
Commands are synchronous and ordered, with at most 1 MiB of data in each wire
request. Read/write, trim and write-zeroes are supported; write-zeroes without
virtio's UNMAP hint sends NBD NO_HOLE. Flush is sent only if the export
advertises FLUSH; otherwise every request was complete before its reply and the
guest's flush completes locally. No FUA, structured replies, TCP,
multiconnection or live drive replacement is implemented.

Guest ranges are validated before I/O. Reads go through dirty-tracked guest
memory writes, including memory supplied through the UFFD backend. Reply
magic/handles and exact transfer lengths are checked. Socket receive/send
operations have 90-second timeouts. Any transport, protocol or backend error
poisons the connection: subsequent operations, including snapshot flush, fail.
No automatic retry can duplicate an ambiguously completed write.

Snapshot preparation uses the existing virtio queue drain/flush path. The state
contains the stable disk path, queues and existing synchronous engine tag; it
contains no live socket FD and introduces no new persisted enum variant. Before
restore, rebind the stable path to the restored sandbox's own export, serving
the matching durable disk layers. Restore opens a new connection and reads a new greeting.
A VMM without NBD backend support cannot restore socket-backed states. Storage
data is not embedded in Firecracker's VM snapshot.

Unit tests exercise chunked I/O, zeroing, guest bounds, dirty tracking, sticky
protocol failure, and activated virtqueue serialization/reconnect. An ignored
integration test, `test_nbd_external_export`, takes `E2B_NBD_TEST_SOCKET` and is
run by E2B's `TestFirecrackerNbdClientAgainstCoWExport` against its real CoW
export. Hardware KVM/UFFD boot, pause/resume, crash cleanup and performance still
need deployment testing. The synchronous engine is a correctness baseline;
it makes no throughput or latency guarantee.

Protocol reference: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
