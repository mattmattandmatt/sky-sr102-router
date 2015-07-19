There is no script to automatically adjust the CFE Bootloader, however if you which to do it manually, here are the steps:


Using the original CFE from SKY-IHR/targets/cfe/bootloader63268.bin_16MB

Extract from Location 0x3894 using 7zip/LZMA decompressor   (You will see a 0x6D0000 Tag)
Disassemble it (MIPS Big-Endian) with a starting memory address of 0x80601000   (Address located at 0x3890)


At address: 0x80608038
Replace the word with 0x00000000.  To ignore the jump and always say 'SIGNATURE OK'.
At address: 0x8060BB18
Replace the word with 0x10000010.  To always take the 0x10 jump and say 'found  SIGNATURE HEADER'.
At address: 0x8060BC08
Replace the word with 0x00000000.  To ignore the jump and always say 'SIGNATURE OK'.
At address: 0x80637980
You may want to change the date string, so you can see the change when you repower the router (the text comes out the serial port).



Recompress the 242K file using these parameters:

Dictionary size:               4 MB (2^22 bytes)
Literal context bits (lc):     1
Literal pos bits (lp):         2
Number of pos bits (pb):       2

The compressed header should be 0x6D0000, and you will find that the top part of the compressed file is the same as the original cfe.
'SKY-IHR/hostTools/lzma457/CPP/7zip/Compress/LZMA_Alone/lzma' will help.
Other parameters may work?, but I recommend you only try other options if you have access to eJTAG.
Normal JTAG does not work, because there is no SAMPLE or EXTEST commands.

Paste the new compressed file back into location 0x3894






Image overview format:


0x000000	++++++++++++++
		+ CFE        +
0x010000	++++++++++++++
		+ NVRAM      +
0x020000	++++++++++++++
		+ EMPTY 128K +
0x040000	++++++++++++++
		+ BCM TAG    +
0x040100	++++++++++++++
		+ ROOT FS    +
0x####00	++++++++++++++
		+ KERNEL     +
0x##0000	++++++++++++++
		+ JFFS2      +
0xFF0000	++++++++++++++
		+ TAGS, ID,  +
		+ & CONFIG   +
		++++++++++++++



