========================
CMIS optical module
========================

``cmis-module`` models an optical transceiver that speaks the Common
Management Interface Specification (CMIS) over I2C, as QSFP-DD, OSFP and
QSFP112 modules do. It exists so that switch and BMC firmware which reads
optics - to report temperatures, to check whether a link partner is present,
or to disable a transmitter - can be developed and tested without the
physical cages.

It is a plain I2C slave, conventionally at address 0x50, and carries no
network traffic itself. Pair it with a mux such as ``pca9548`` to model a
cage array, where each downstream bus is one port.

Usage
-----

.. code-block:: console

   -device pca9548,bus=aspeed.i2c.bus.3,address=0x70,id=mux
   -device cmis-module,bus=mux.0,address=0x50,serial-number=CAGE-0
   -device cmis-module,bus=mux.1,address=0x50,serial-number=CAGE-1

Properties
----------

``temperature``
  Module temperature in millidegrees Celsius. Default 35000.

``voltage``
  Supply voltage in millivolts. Default 3300.

``tx-power``, ``rx-power``
  Per-lane optical power in microwatts. Defaults 1000 and 900.

``tx-bias``
  Per-lane transmitter bias current in microamps. Default 7000.

``lanes``
  Number of host lanes, 1 to 8. Default 8.

``vendor-name``, ``part-number``, ``serial-number``, ``revision``, ``date-code``
  Identity strings reported on upper page 00h. Each is padded with spaces or
  truncated to the width CMIS defines for it.

Giving each instance a distinct ``serial-number`` is what lets firmware tell
one cage from another, and staggering ``temperature`` across instances makes
a firmware sweep produce visibly different readings rather than a column of
identical numbers.

Memory map
----------

CMIS presents a 128 byte lower page that is always visible, and a 128 byte
upper page selected by writing the page number to byte 127. Byte offsets
below are absolute, as CMIS states them.

Lower page (always visible)

===== ============================================================
Byte  Contents
===== ============================================================
0     Identifier. 0x18, QSFP-DD.
1     CMIS revision.
2     Memory model.
3     Module state. Reports ModuleReady.
14    Temperature, int16 big endian, units of 1/256 degree C.
16    Supply voltage, uint16 big endian, units of 100 uV.
85    Media type. 0x02, single mode fibre.
126   Bank select.
127   Page select.
===== ============================================================

Upper page 00h, module identity

===== ============================================================
Byte  Contents
===== ============================================================
129   Vendor name, 16 ASCII, space padded.
145   Vendor IEEE OUI, 3 bytes.
148   Vendor part number, 16 ASCII.
164   Vendor revision, 2 ASCII.
166   Vendor serial number, 16 ASCII.
182   Date code, 8 ASCII.
222   Checksum over bytes 128 to 221.
===== ============================================================

Upper page 02h holds the alarm and warning thresholds: temperature at byte
128 and voltage at byte 136, each a set of four int16 values in the order
high alarm, low alarm, high warning, low warning.

Upper page 10h holds the per-lane controls. Byte 130 is TxDisable, one bit
per lane.

Upper page 11h holds the per-lane diagnostics, each an array of uint16 values
in big-endian order: transmitter bias at byte 138 in units of 2 uA,
transmitter power at byte 154 and receiver power at byte 170, both in units
of 0.1 uW.

A lane whose TxDisable bit is set reports zero transmitter bias and zero
transmitter power, which is what firmware uses to confirm that a disable
took effect. Receiver power is unaffected, since disabling the local
transmitter does not stop light arriving from the far end.

Only the pages listed above are implemented. Reads of an unimplemented page
return zeroes rather than failing, because firmware commonly walks pages
speculatively.
