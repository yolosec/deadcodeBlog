---
layout: post
title:  "Wardriving Bratislava 10/2016"
date:   2016-11-05 08:00:00 +0200
categories: blog
tags: wardriving bratislava UPC router wifi kismet wiggle ubee compal mercury
excerpt_separator: <!-- more -->

---

TL;DR: Wardriving in Bratislava, Slovak Republic capital city, 8 months after contacting UPC about
 the flaw in their insecure default password generation.

<!-- more -->

## Intro

In the previous article, [UPC UBEE EVW3226 WPA2 Password Reverse Engineering], we analyzed UPC UBEE router and found serious
flaws in generating a default password for the WiFi.
People using the default password were in potential danger, attackers could tamper with the router or their LAN.

A part of the article was also Wardriving in Brno, Czech Republic. We discovered there were vulnerable routers
out there. After 8 months we found it interesting to repeat the wardriving experiment in a different city to see
whether the pattern changed.

## Setup

* Motorola Moto G Android phone with WiGLE [WiGLE Wifi](https://play.google.com/store/apps/details?id=net.wigle.wigleandroid) application
* [Ovislink Airlive WL-1600USB](https://www.cnet.com/products/ovislink-airlive-wl-1600usb-network-adapter/) + 5dBi antenna
running with the [Kismet](https://en.wikipedia.org/wiki/Kismet_(software))

## Methodology

We carried out only the passive Wardriving with 2 measurement devices on board of the car. The cruise speed was kept low,
 around 10 kmph in dense residential urban areas of Bratislava (mainly Petrzalka) in the middle of the night. At some more interesting
 places we stayed for a longer time.

Then for a random sample verification we passively captured WPA2 handshake for 20 WPA2
protected networks and performed the password check - for UBEE it matched in 100% cases.

The fun thing about 2 guys in the car going 10 kmph in the middle of the night in the dark streets is that you either look
as a drug dealer or looking for one. At one dark street two weird hooded guys started approaching us,
maybe thinking one of the two above so we decided to move to another place. We did not encounter any police car whatsoever
during the experiment.

## Results

[![Wardriving map](/static/wdriving/map_ba.png)](/static/wdriving/ba-live-map.html)

* Wardriving experiment took place 01/10/2016.
* Dark dots represent non-categorized WiFi
* Blue markers correspond to `^UPC` SSID pattern (excluding UPC WiFree)
* Green markers are UBEE routers with `^UPC[0-9]{7}` SSID

The original KML map data are available for download, for older
[Brno experiment](/static/wdriving/wdriving1.kml) and this new
[Bratislava experiment](/static/wdriving/wdriving2.kml). To get the idea on
how wifileaks dataset is geo distributed we sampled 20k UPC networks from 2015-2016
from the wifileaks dataset to the [wifileaks KML](/static/wdriving/wdriving_wifileaks_20k.kml.gz)
(sampling was necessary as the original dataset is too large to plot on GoogleMaps, all non-UPC networks
were excluded from the dataset).

By plugging KML files to the [GPS Visualizer](http://www.gpsvisualizer.com/) you can browse
the map interactively. Here is [the online interactive wardriving map for Bratislava](/static/wdriving/ba-live-map.html)
(2 or 3 WiFis are obviously mis-localized as we have never been to Cunovo). For completeness
we provide also the [online interactive wardriving map for Brno](/static/ubee/brno-live-map.html)
and sample of the [wifileaks interactive map](/static/wdriving/wifileaks-live-map-20ksample.html).

Below are the results from the Wardriving experiment, combining both data sets - Wiggle and Kismet.

| Statistic - Bratislava 1.10.2016 | Count         | Ratio           |
| :------------------------------- | :------------ | :-------------- |
| Total networks                   | 22 172        |                 |
| UPC networks                     | 3 092         | 13.95 %         |
| UPC vulnerable                   | 1 327         | 42.92 % UPC     |
| UPC UBEE vulnerable              | 822           | 26.58 % UPC     |
| UPC Technicolor vulnerable       | 505           | 16.33 % UPC     |
| UBEE changed                     | 205           | 19.96 % UBEE    |
| Technicolor changed              | 96            | 19.00 % Tech.   |
| Compal CH7465LG                  | 930           | 30.08 % UPC     |
{:.mbtablestyle3}

<br/>
For the comparison we state the similar table from the previous wardriving in Brno:

| Statistic - Brno 10.2.2016    | Count         | Ratio           |
| :---------------------------- | :------------ | :-------------- |
| Total networks                | 17 516        |                 |
| UPC networks                  | 2 868         | 16.37 %         |
| UPC vulnerable                | 1 835         | 63.98 % UPC     |
| UPC UBEE vulnerable           | 443           | 15.45 % UPC     |
| UPC Technicolor vulnerable    | 1 392         | 48.54 % UPC     |
| UBEE changed                  | 98            | 18.11 % UBEE    |
| Technicolor changed           | 304           | 17.92 % Tech.   |
| Compal CH7465LG               | 0             | 00.00 % UPC     |
{:.mbtablestyle3}

<br/>
The more detailed analysis of the datasets are available:
[Brno dataset results](/static/wdriving/analysis_brno.txt) and new
[Bratislava dataset results](/static/wdriving/analysis_bratislava.txt).

## Discussion

The Technicolor vulnerable data count is based on the known MAC addresses of the
router that we detected to respond to the [Blasty attack](https://haxx.in/upc-wifi/).

Interestingly the amount of UBEE routers with changed password is about the same 18%. This may represent
sample of users changing the default settings more globally. This pattern moreover holds also in the
[Wifileaks] analysis from the previous article. The ratio of people leaving the router in default settings
is disturbingly high.

Technicolor routers ratio dramatically dropped in Bratislava compared to Brno (48.54 % to 16.33 %).
UBEE routers also had a slight drop (19.96 % to 15.45 %) but we have to conclude that 8 months after
reporting vulnerabilities to UPC the situation does not look much different...

UPC drafted a solution with captive portal making users change their default passwords. Apparently this
feature was not present in the UBEE firmware update which was rolled out in 20.9.2016. My own router
has a new firmware with version `EVW3226_2.07b`, in the time of writing the first article it was `EVW3226_1.0.20`.
It would be interesting to test how many vulnerabilities were fixed...

Another new interesting observation is a new router type detected in the data. It is
[Compal CH7465LG](https://www.upc.cz/pdf/manualy_inet/15258_UPC_Mercury_modem_uzivatelsky_manual_v5.pdf)
also called a Mercury modem by UPC. The typical SSID matches the regex pattern `^UPC[0-9A-F]{7}`, it
contains also hex digits. The example password (from the linked user manual is): `x*Hz6mh4ppdcx`
which looks quite complicated. But if the same pattern is followed the brute-force search space can be
reduced.

The router was extensively analysed by other researchers, here is the 100 pages long [Compal CH7465LG evaluation report].
They found 35 vulnerabilities in this router (11 found in UBEE). So it looks much worse in many aspects compared to UBEE.
 _Allegedly_ the password generation routine is implemented in a secure way. We would like to verify this so if somebody has
firmware dumps or the hardware itself we are interested in buying the piece for analysis. Let us know at `yolosec.team@gmail.com`.

The router looks like this:

[![Compal CH7465LG](/static/wdriving/compal.png)](/static/wdriving/compal.png)

To conclude the dataset results it seems that UPC decided not to deal with UBEE and Technicolor vulnerabilities in
any direct manner. It is maybe much easier and economical to let those routers go out of the market
by making users upgrade to new Compal routers.

On a side note: after I searched this router a bit when analysing wardriving results I started seeing adds like this:

[![Compal CH7465LG ad](/static/wdriving/compal_ad.png)](/static/wdriving/compal_ad.png)

Yep, that's the router I am talking about. UPC is asking me to upgrade to mega-strong UPC WiFi router (security swiss cheese).

## Bonus: photos
Due to popular demand, here are some photos from the wardriving action. We rode streets of Bratislava in the evening and early morning hours and went to bunch of interesting places and "landmarks" such as Grassalkovich Palace (seat of Slovak president), UPC headquarters and Bonaparte complex (infamous residence of Slovak prime minister). It seems that neither our president or prime minister is using UPC UBEE router, luckily for them.

[![Grassalkovich Palace](/static/wdriving/president.jpg)](/static/wdriving/president.jpg)

[![UPC headquarters](/static/wdriving/upc_headquaters.jpg)](/static/wdriving/upc_headquaters.jpg)

[![Bonaparte](/static/wdriving/bonaparte.jpg)](/static/wdriving/bonaparte.jpg)

[UPC UBEE EVW3226 WPA2 Password Reverse Engineering]: https://deadcode.me/blog/2016/07/01/UPC-UBEE-EVW3226-WPA2-Reversing.html
[Wifileaks]: https://deadcode.me/blog/2016/07/01/UPC-UBEE-EVW3226-WPA2-Reversing.html#wifileaks
[Compal CH7465LG evaluation report]: http://www.search-lab.hu/media/Compal_CH7465LG_Evaluation_Report_1.1.pdf

