DeBrick instructions for the BCM963168 Sky SR102 Router:

You need a 3.3v parallel port.  If you have a 5v one, you could try using some 330 Ohm resisters in-series with the 2,3,4 pins.
Connect it like a Xilinx DLC5 cable, the pictures explain it.



Router		Parallel	Pin
Header		Port		Name

6		2		TDI
9		3		TCK
8		4		TMS
7		13		TDO
The 'I/O reset pulse' is the nTRST, so tie that to +V.  Ignore the Master Reset pin.


Start "jtag-win.exe" and type the following:

cable dlc5 parallel 0x378
detect
initbus ejtag
poop 0 sky-sr102-cfe.bin


When it has finished. Repower the router... connect to http://192.168.0.1 and upload the firmware/kernel.
I dont recommend uploading the whole flash from this program, because it will take hours.



If you have corrupted the nvram and it is refusing to fully boot.
   Then add the dummy nvram.bin from the '_cfe-adjustments' directory starting at 0x10000.







Other points (if you like playing about):
-----------------------------------------
If you want to backup the cfe without burning:
> readmem 0xb8000000 0x10000 cfe-backup.bin
or
> readmem 0xb8000000 0x20000 cfe-backup-with-nvram.bin   # contains the default passwords

If it can not read the flash properly, e.g. all 0xFF's.  The use the 'poop' command with a bad file name.  This will reset the flash chip.



If you are interested in the test points next to the flash.  Use this command to slow some of the communication:
> poke 0xb0001100 0x800A   # slow down to ~2Mhz for normal peeks/pokes



You can change the normal 'read' opcode to e.g. get Chip ID:
> poke 0xb0001014 0x90
then
> peek 0xb8000000
However... It always ignores the first 2 bytes after the Instruction is sent, so OpCode 0x9F will miss the Chip ID.

Back to normal:
> poke 0xb0001014 0x50B   # the 5 implies it misses some extra address/dummy bytes.



> poke 0xb0001014 0x05   # Status Reg 1
> poke 0xb0001014 0x07   # Status Reg 2
> poke 0xb0001014 0x35   # Config Register



I included a compiled ubuntu-x86 version as well, because it might be useful to someone?.  But I have not tested it !



Good Luck
Matt Goring - Feb 2015
