#! /bin/sh

# Loop around for 30 seconds, until the file 'appears' after mount has finished

i=0
while [ $i -lt 10 ]
do
	sleep 3

	if [ -f /var/auxfs/init2.sh ];
	then
		/var/auxfs/init2.sh &
		exit
	fi
	
#	i=`expr $i + 1`
	i=$((i+1))
done
