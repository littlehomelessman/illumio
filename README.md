# illumio coding challenge


## Use the code:

Download `FireWall.java` and `rules.csv`

Class: FireWall

API: acceptPacket(direction, protocol, port, IP\_address)
```java
FireWall fw = new FireWall(path);
fw.acceptPacket("inbound","tcp",80,"192.168.1.2")
```


Terminal command (make sure &quot;FireWall.java&quot; and &quot;rules.csv&quot; must be located properly):

```bash
javac FireWall.java
java FireWall
```
Test cases have been included in the `main` function of the `FireWall` class. Both imported rules &amp; test results will be shown after running the code directly.



## Brief Introduction:

This project aims to create a simplified firewall that blocks/allows traffic that match one of the predefined rules only.

Naïve solution is nothing but a simple string-matching problem. Since many languages have already provide lots of APIs for strings, it is not a difficult task. The expected time complexity for checking packet is O(nm) where n is the number of rules and m is the average total length of each rule.

In order to deal with a situation where the traffic is &quot;busy&quot;, we need to parse the packet and filter out some of the unmatched rules quickly. As a result, I came up with a Tree-like mapping structure shown as follows:

![](/mapping_structure2.png)

<p align=center>Fig.1

![](/mapping_structure.png)

<p align=center>Fig.2

## Assumptions for this project:

1. The input files contain only valid, well-define entries. Each attribute will rigorously fall into its definition. For example, &quot;direction&quot; can either be &quot;inbound&quot; or &quot;outbound&quot;
2. The port and IP address do not overlap respectively.

## Mapping Structure:

The first level mapping composes the combination of direction + protocol as the key and a **sorted** list of ports under such a combination as the value; The second level mapping contains each port as the key and the **sorted** list of IP address as its value; The reason for keeping the ports list and IP address list sorted is to make sure the binary search algorithm can be performed during the verifying process.

The time complexity for creating such structure is O(n \* m + 4(klogk + k \* hlogh)) = O(n \* m) where n is the number of rules, m is the average total length of each rule, k is the average number of ports for each key in layer 1 mapping, h is the average number of IP address for each port. The &quot;k&quot; and &quot;h&quot; are smaller than &quot;m&quot;.



## Verifying Process:

Once the complete mapping structure is built and a set of direction, protocol, port and IP address are given. We may start checking if this packet should be allowed.

First of all, since both direction and protocol are simplified as &quot;inbound &amp; outbound&quot; and &quot;udp &amp; tcp&quot; respectively, there are only four keys (direction + protocol). Thus, it is easy to rule out 3/4 of the total number of rules initially (Given that all rules are evenly distributed).

Second, we need to use binary search to find out whether the packet port is contained under the &quot;direction + protocol&quot; combination.

Third, if we can locate such a port in the mapping structure, again, we can use binary search to find if the packet IP address exists along with the valid port.

Finally, we can conclude whether this packet can be allowed.

The expected time complexity for verifying process is O(1 + logk + logh) where the first step only cost constant time if we use the HashMap, k is the average number of ports for each key in layer 1 mapping, h is the average number of IP address for each port. Both &quot;logk&quot; and &quot;logh&quot; are spent on binary search on Layer2 and Layer3.

As we can see, comparing to the naïve solution where the matching process will take O(n \* m) time, we can significantly reduce the complexity using the structure above. Although creating such a structure should cause some overhead, it is likely a one-time cost. We still benefit from the reduced complexity during the verifying process.

## Comparing IP address:

Defining the magnitude relationship among ports is simple: the natural relationship of numbers is good enough.

Since we sort the IPs, we must come up with a comparator among IP addresses as well. Because Java has the limitation on the integer size, I ended up using an integer array to store consecutive parts within an IP address. The pseudo code of the conversion and comparison are as follows:

 ![](/compare.png)
 <p align=center>Fig.2
 
## Team that I&#39;m interested:

Most interested → Less interested

Platform Team → Data Team → Policy Team

