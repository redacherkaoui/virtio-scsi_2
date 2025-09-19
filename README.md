Time-of-Check Time-of-Use (TOCTOU) race condition in QEMU's virtio-scsi implementation.

## The Primitive

**Core issue:** QEMU reads `vs->cdb_size` twice without synchronization:

1. **First read** - `virtio_scsi_pop_req()`: Allocates buffer using current `vs->cdb_size`
2. **Second read** - `virtio_scsi_parse_req()`: Copies data using current `vs->cdb_size`

**Race window:** Between these two reads, a guest can update `vs->cdb_size` via virtio config writes.

## Exploitation Sequence

**Step 1:** Guest triggers SCSI I/O operation
- QEMU calls `virtio_scsi_pop_req()`
- Reads `vs->cdb_size = 32`
- Allocates small buffer (e.g., 48 bytes)

**Step 2:** Guest flips config during processing
- Writes `cdb_size = 128` to virtio config space
- QEMU calls `virtio_scsi_set_config()`
- Updates `vs->cdb_size = 128`

**Step 3:** QEMU continues processing same request
- Calls `virtio_scsi_parse_req()`
- Reads updated `vs->cdb_size = 128`
- Copies large payload (144 bytes) into small buffer (48 bytes)

**Result:** Heap buffer overflow - 96 bytes of overflow data overwrites adjacent heap chunks.

The primitive exploits the lack of atomicity between allocation size determination and copy size determination, allowing a guest to cause QEMU to copy more data than it allocated space for.
