=========================
Cnuas virtual NIC
=========================

``cnuas-vnic`` is a PCIe network device whose wire side is a UNIX socket
rather than a QEMU netdev. It exists to let a virtual fabric be built out of
ordinary processes: each guest's NIC connects to a switch model listening on
a socket, so a multi-node RDMA or Ethernet topology can be assembled, torn
down and inspected on one host with no privileged networking setup.

It is deliberately simple. There are no descriptor rings; a transmit is one
doorbell write against one guest-physical address, and a receive lands in one
guest-physical address the driver nominated in advance. That keeps the device
small enough to reason about while still exercising the parts of a driver
that matter - DMA, interrupts, link state.

PCI properties
--------------

===================== ==========================================
Vendor ID             1af4 (experimental range, see `pci-ids`)
Device ID             10f0
Revision              0
Class                 0200, Network controller, other
===================== ==========================================

BAR 0 is a 4 KiB MMIO register window. The device supports a single MSI
vector and also asserts INTx.

Options
-------

``socket_path``
  Path of the ``AF_UNIX`` ``SOCK_SEQPACKET`` socket to connect to. Without
  it the device still enumerates but reports the link down, which is a
  useful state to test drivers against.

``mac``
  MAC address, readable by the guest through ``REG_MAC_LO`` and
  ``REG_MAC_HI``. Each instance needs its own.

``x-speed``, ``x-width``
  PCIe link speed and width reported in the Link Capabilities register.

Register map
------------

All registers are 32 bit and are read/write unless stated otherwise.

======  ==================  =========================================
Offset  Name                Meaning
======  ==================  =========================================
0x00    TX_ADDR_LO          Guest-physical address of the frame to send
0x04    TX_ADDR_HI          Upper half of the same address
0x08    TX_LEN              Frame length in bytes, 1 to 9216
0x0c    TX_DOORBELL         Write to transmit
0x10    RX_ADDR_LO          Guest-physical address to land frames in
0x14    RX_ADDR_HI          Upper half of the same address
0x18    RX_LEN              Read only. Length of the frame delivered
0x1c    RX_STATUS           1 when a frame is waiting; write 0 to release
0x20    IRQ_STATUS          Write ones to clear
0x24    IRQ_MASK            Set a bit to allow that interrupt
0x28    LINK_STATUS         Read only. Bit 0 set when the socket is
                            connected
0x2c    MAC_LO              Read only. MAC bytes 0 to 3, byte 0 in the
                            least significant position
0x30    MAC_HI              Read only. MAC bytes 4 and 5
======  ==================  =========================================

Interrupt bits, shared by ``IRQ_STATUS`` and ``IRQ_MASK``:

===== ==================================================
Bit   Meaning
===== ==================================================
0     A received frame is available
1     A transmit has completed
2     The link state changed
===== ==================================================

Transmitting
------------

Write the frame's address and length, then write ``TX_DOORBELL``. The device
reads the frame out of guest memory and sends it as one datagram, then raises
bit 1 of ``IRQ_STATUS``.

A length of zero or above 9216 is rejected and logged as a guest error. If
the link is down the frame is discarded, but the completion interrupt is
still raised, so a driver does not stall waiting for a transmit that can
never land.

Receiving
---------

The driver nominates a landing address in ``RX_ADDR_LO`` and ``RX_ADDR_HI``.
When a datagram arrives the device writes it there, sets ``RX_LEN``, sets
``RX_STATUS`` to 1 and raises bit 0 of ``IRQ_STATUS``.

The driver releases the buffer by writing 0 to ``RX_STATUS``. If another
frame is already queued on the socket it is delivered immediately from that
write rather than after another round trip through the event loop, which is
what keeps small-packet rates reasonable.

While ``RX_STATUS`` is 1 the device does not read from the socket, so flow
control is exerted on the socket itself rather than by dropping frames.

The one case where a frame is dropped is when no landing address has been
posted yet: a frame that arrives while ``RX_ADDR_LO`` and ``RX_ADDR_HI`` are
both zero is discarded, which is what a real NIC does with an unarmed ring.

Wire format
-----------

The socket carries bare Ethernet frames with no header of QEMU's own. Message
boundaries come from ``SOCK_SEQPACKET``, which is why the type matters: a
stream socket would need a length prefix and would let two frames coalesce.

Send and receive buffers are enlarged at connect time so that a burst of
fragments belonging to one higher-level message does not overflow the socket
while the guest is still draining the previous frame.
