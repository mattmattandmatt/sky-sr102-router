CIFS/SAMBA/Windows File Sharing:

insmod nls_base.ko
insmod cifs.ko
mkdir /mnt/on-the-router
mount -t cifs //192.168.0.99/on-the-pc /mnt/on-the-router -o user=123,pass=123
