This 'directory' is not really related to the other stuff on this github page, but its close enough so I'll put it here.

This firmware was not compiled from any source code.  I have just adjusted the latest (mid 2017) from SKY, so its not very flexable.
Its main purpose is to remove the remote managment and change the DSL Username/Password for use with another ISP.




List of changes to the firmware:
--------------------------------

Deleted some sd* blocks from /dev/

Deleted from /bin/:
	factory
	fus
	rtm
	tr69c
	tr143DownloadDiag
	tr143EchoCfgServer
	tr143UploadDiag
Removed 'fus' tmpfs from /etc/fstab

Replaced /bin/busybox with more commands & added some symlinks.

Added 2 symlinks in /etc/rc3.d/ to:
	/data/S27extra-mounts
	/data/S61user-exec

Added /var/web_sym_link.html symlink in /webs/web_sym_link.html   (handy link)

Added /usr/bin/utelnetd & /usr/bin/telnet-console.sh   (telnet enabled on port 2323)
Added /etc/init.d/telnet.sh with symlink in /etc/rc3.d/S70telnet

Adjusted /bin/httpd to remove "X-Frame-Options: Deny"   (0'd out the start of text)
Added Broadcom HTML files to /webs/, but are not useful in the current state.

Adjusted /lib/public/libcms_util.so to skip the Signature check.   (Addr: 0x1AD2B = 0xE2)

Added /usr/bin/serialize to change the default Username/Passwords for other ISPs.

Adjusted /webs/
	assets/images/sky_logo*.png
	sky_router_upgrade.html
	sky_wan_setup.html
	sky_license.html



Side Effect:
Although the tr69c port 30005 is closed, the firwall rule still exists.  So any connection to it will reject not drop.
If you are bothered... you can add a script in /data/S61user-exec   (remember to chmod a+x)







To Burn the Image:
------------------

Run a local mini HTTP server & Connect to the serial port:

	Login: admin
	Password: sky
	sh
	
	mount -o remount,rw,size=20M tmpfs /var
	cd /var
	wget http://192.168.0.2:8000/burn-whole-image2
	wget http://192.168.0.2:8000/SKY-SR102-2-9-1-6666-R.whole-image.w
	chmod a+rwx ./burn-whole-image2
	./burn-whole-image2 danger SKY-SR102-2-9-1-6666-R.whole-image.w



This program 'burn-whole-image2' has been tested on only 2 firmwares:
Oldest 2013 Recovery FW	(2.1m.3173.R)
Latest 2017 FW			(2.91.2110.R)

* It expects a file which has a CFE/Bootloader at the beginning *










Other stuff:
------------

If you want to disable IPv6 (for some reason):
	sysctl -w net.ipv6.conf.all.disable_ipv6=1
You can make it apply on every boot by adding that line to:   /data/S61user-exec   (this will have bad side effects)


To dump the current flash:
Copy flash_dump.ko to /var/
	mount -o remount,rw,size=36M tmpfs /var
	insmod ./flash_dump.ko
After a minute copy /var/flash_dump.bin to your PC.  The program dumps 32MB so only use the first 16MB.
* In theory this could crash your router, so you might need to repower *


Bridge Mode is probably configurable in the XML config file.  Side Effect: some of the web pages on the router wont work, and does not work with SKY Broadband.


If you are going to compile programs for it.  Use the SR102 source, but the ER115 toolchain !
