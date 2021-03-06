---
layout: post
title:  "Active WiFi deauth with Kismet for Wardriving"
date:   2016-11-05 07:00:00 +0200
categories: blog
tags: wardriving kismet airodump aircrack
excerpt_separator: <!-- more -->

---

TL;DR: Actively sniffing WPA2 handshakes during the wardriving with sending deauth packets.

<!-- more -->

## Kismet active deauth
During our wardriving experiments we were flirting with an idea of active wardriving to validate our results
on vulnerability of the routers. We had to abandon this idea due to legality issues. But it initiated our
curiosity on how complicated it is to build such setup.

In order to test the WPA2 password, the first thing you need is to capture
[WPA2 handshake](https://www.aircrack-ng.org/doku.php?id=cracking_wpa), this you can
do by sniffing WiFi transmission (in monitor mode) by `airodump-ng` utility.

Once you have that you can try the dictionary/bruteforce attack offline on the handshake. Handshake occurs only
when a client connects to the network. This event is quite rare as many devices keep persistent WiFi connection.
You would have to wait until somebody walks in/out from the range of the WiFi access point with the smartphone in the pocket or
something like that.

To get the handshake you can actively deauthenticate the client from the network by sending a special deauth
 packet to the client. For this you obviously need an existing client in the network and antenna & transmitter strong
 enough so your packet hits the client.

This causes client to drop the connection to AP and reconnect again. Here you can capture the new handshake and then attack offline,
out of the AP WiFi reach.

The following command sends 3 deauth packets to the client `22:33:44:55:66:77` connected to AP with BSSID `00:11:22:33:44:55`
via interface wifi0. Wifi0 has to be in the monitor mode and driver need to support packet injection.

```
/usr/sbin/aireplay-ng -0 3 -D -a 00:11:22:33:44:55 -c 22:33:44:55:66:77 wifi0
```

## Automation

We were thinking about automating this deauth & handshake collection during the wardriving. For this the
[Kismet](https://en.wikipedia.org/wiki/Kismet_(software)) is an ideal candidate. It is quite good tool for wardriving and
moreover it provides a nice API for plugins via sockets.

So we created a *[kismet-deauth-plugin]* in python. For more detailed information on using the plugin please see the GitHub repo readme.

For this you need 2 WiFi interfaces to work smoothly:

1. Is running Kismet, jumping over channels and collecting stats about
networks and connected clients. Should have a very high gain. Listening only.
2. Is for collecting handshakes and actively deauthenticating clients.
Ideally you need a strong transmitter on this one to successfully hit the client
with deauth packet, something like [Alpha](https://www.amazon.com/Alfa-802-11b-Wireless-Original-9dBi/dp/B001O9X9EU).

It works in the following way:

* You start the Kismet with the kismet server as you do usually.
* Kismet server listens on a socket `127.0.0.1:2501` - here we can register event handlers and listen for it.
* In a new terminal you run our python plugin which performs the following if a new client is detected
  * Starts airodump-ng on given channel
  * Sends 3 deauth packets to the client
  * Stops airodump-ng after 10 seconds.

Plugin goes according to the priority queue which is built on the client list. The newer client has higher priority.

## Testing

We were testing this in our home network, the plugin worked quite well. We were able to automatically capture
WPA2 handshakes with this. Unfortunately after some time the driver for deauth card broke. Drivers were not stable
enough to support this approach for longer than 30 minutes.

## Use-case

As some commenter on Reddit pointed out, this approach is not new. That's correct, deauth is pretty old stuff. Our contrinution
is a demonstration of an automatic deauth + handshake collection without manual intervention, with Kismet and simple plugin.
You drive the car, the plugin tries to deauth interesting clients and collect handshakes. Without even touching a keyboard.
I was not able to find such stuff (we also needed some filtering, priority, ...) so I implemented it.

After the experiment you can run some dictionary attack for all collected data and typically crack some default passwords,
routers with default ones (e.g., admin, tplink, airlive), routers with flaws in default password generation - UPC. This
may come handy also for hacking IoT in a large scale. This approach is good for mass attacks in a large area, not for
targeted attack against one particular victim.

## Disclaimer

Actively deauthenticating client is illegal, you should do this only in your own network. We declare we didn't
use the plugin in the wild outside the controlled environment.


[kismet-deauth-plugin]: https://github.com/ph4r05/kismet-deauth-wpa2-handshake-plugin
