Write Firmware on the Sky Router SR102
---------------------------------------

Connect TTL Serial port to pins 1(optional),2,3,4   (or telnet)
Backup current Settings
start a http miniweb server


Login: admin
Password: sky
sh


# If you need to lower the baud rate, due to the in-line 1K resistors & homemade adapters
stty -F /dev/ttyS0 9600


cd /var
wget http://192.168.0.2:8000/burn_whole_image
wget http://192.168.0.2:8000/SR102-whole-image-XXXX.bin
chmod 0777 ./burn_whole_image
./burn_whole_image danger SR102-whole-image-XXXX.bin


# This preserves your original serialisation/nvram data.
# It may crash/oops after its finished burning, dont worry, it will reset either way.





# Remember to change your passwords, it IS your biggest weakness





Other information (for playing about)
-------------------------------------

# Kill all processes
setmem 0xb000009c 0 4   # Stop Watchdog
echo i > /proc/sysrq-trigger



# Backup the current Firmware, Config or File
# start a ftpd server
ftpput -u 123 -p 123 192.168.0.2 mtd0.squashfs /dev/mtdblock0
ftpput -u 123 -p 123 192.168.0.2 mtd1.jffs2    /dev/mtdblock1
ftpput -u 123 -p 123 192.168.0.2 entire.flash  /dev/mtdblock6



# Read the first 28 bytes of raw flash (ignore the first word delay)
echo p 1 0 6 0x03000000 32 > /proc/bcmlog

# Show Chip ID
dumpmem 0xb0000000 4
