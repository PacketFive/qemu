=========================
HiGPU virtual accelerator
=========================

``higpu`` is a PCIe accelerator model. It is not an emulation of any real
GPU and executes no kernels; what it provides is the shape of one - an
identification block, a large device-memory BAR, an interrupt path, and a
peer-to-peer link. That is enough to develop and test the software that sits
above an accelerator (runtimes, allocators, drivers, fabric managers) and to
exercise multi-device collectives, without the silicon.

The peer link, HiLink, is a UNIX socket carrying frames pulled straight out
of device memory. It models the direct device-to-device path that
accelerators use for collectives, and lets a topology of several HiGPUs be
wired together as ordinary host processes.

PCI properties
--------------

===================== ==========================================
Vendor ID             1af4 (experimental range, see `pci-ids`)
Device ID             10f1
Revision              1
Class                 0b40, Co-processor
===================== ==========================================

======  ====================================================
BAR     Contents
======  ====================================================
0       64 KiB of MMIO registers
1       Device memory, 64 bit prefetchable, 256 MiB default
======  ====================================================

The device supports a single MSI vector and also asserts INTx.

Options
-------

``gpu_id``
  Identifier the guest reads back from ``REG_GPU_ID``. Give each device in
  a topology its own.

``sm_count``, ``lanes_per_sm``, ``tensor_size``
  Advertised geometry, default 16, 32 and 16. Purely descriptive: the
  device does no work, but a runtime's sizing and scheduling logic can be
  driven from these.

``devmem_size``
  Size of BAR 1, default 256 MiB.

``hilink_socket``
  Path of the ``AF_UNIX`` ``SOCK_SEQPACKET`` socket for the peer link.
  Without it the device works normally but reports the link down.

``x-speed``, ``x-width``
  PCIe link speed and width, default 32 GT/s and x16.

Register map
------------

All registers are 32 bit.

Identification, all read only:

======  ==================  =========================================
Offset  Name                Meaning
======  ==================  =========================================
0x000   VENDOR_ID           0x1af4
0x004   DEVICE_ID           0x10f1
0x008   REVISION            0x01
0x00c   FW_VERSION          0x00010000, meaning 0.1.0
0x010   GPU_ID              The ``gpu_id`` property
0x014   SM_COUNT            The ``sm_count`` property
0x018   LANES_PER_SM        The ``lanes_per_sm`` property
0x01c   TENSOR_SIZE         The ``tensor_size`` property
0x020   DEVMEM_SIZE_LO      Size of BAR 1, low half
0x024   DEVMEM_SIZE_HI      Size of BAR 1, high half
======  ==================  =========================================

Interrupts:

======  ==================  =========================================
Offset  Name                Meaning
======  ==================  =========================================
0x100   IRQ_STATUS          Write ones to clear
0x104   IRQ_MASK            Set a bit to allow that interrupt
======  ==================  =========================================

===== ==================================================
Bit   Meaning
===== ==================================================
0     A HiLink transmit has completed
1     A HiLink frame is available
===== ==================================================

HiLink:

======  ==================  =========================================
Offset  Name                Meaning
======  ==================  =========================================
0x200   LINK_STATUS         Read only. Bit 0 link up, bit 1 a received
                            frame is waiting to be consumed
0x204   LINK_TX_OFFSET_LO   BAR 1 offset of the frame to send
0x208   LINK_TX_OFFSET_HI   Upper half of that offset
0x20c   LINK_TX_LEN         Frame length in bytes, 1 to 65536
0x210   LINK_TX_DOORBELL    Write non-zero to send
0x214   LINK_RX_OFFSET_LO   BAR 1 offset to land frames in
0x218   LINK_RX_OFFSET_HI   Upper half of that offset
0x21c   LINK_RX_BUF_SIZE    Bytes the guest is willing to accept
0x220   LINK_RX_LEN         Read only. Length of the frame delivered
0x224   LINK_RX_CONSUME     Write non-zero once the frame is read
======  ==================  =========================================

Sending over HiLink
-------------------

Write the offset and length of a buffer that lives in BAR 1, then write
``LINK_TX_DOORBELL``. The device sends those bytes as one datagram and raises
bit 0 of ``IRQ_STATUS``.

Because the source is device memory rather than guest RAM, no DMA is
involved and no address translation applies. The offset and length are
checked against the size of BAR 1 and a request that runs past the end is
rejected and logged, as is a length of zero or above 64 KiB.

If the link is down the doorbell does nothing at all - no frame, and no
completion interrupt. Drivers must therefore check ``LINK_STATUS`` before
sending rather than waiting on a completion that will not arrive.

Receiving over HiLink
---------------------

Arm the receive path by writing ``LINK_RX_OFFSET_LO``, ``LINK_RX_OFFSET_HI``
and ``LINK_RX_BUF_SIZE``. When a datagram arrives the device copies it into
BAR 1 at that offset, sets ``LINK_RX_LEN``, and raises bit 1 of
``IRQ_STATUS``. The driver reads the frame out of device memory and then
writes ``LINK_RX_CONSUME`` to release the buffer.

Until it does, the device stops reading the socket, so frames queue on the
socket instead of overwriting one another.

Two cases drop a frame, both logged as guest errors: arriving before any
buffer is armed, meaning ``LINK_RX_BUF_SIZE`` is still zero, and arriving
larger than the armed buffer. There is no partial delivery and no
fragmentation.

If the peer closes the socket, or a send or receive fails, the link is torn
down and ``LINK_STATUS`` reads back down.
