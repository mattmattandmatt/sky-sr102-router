#!/bin/bash
filesize=$(stat -c '%s' $1)
padsize=$(expr $((16#FB0000)) - $filesize)
dd if=/dev/zero ibs=1 count=$padsize | tr "\000" "\377" > padding-file.bin
