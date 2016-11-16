# 第三章 端口扫描

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 3.1 UDP端口扫描

由于 TCP 是更加常用的传输层协议，使用 UDP 的服务常常被人遗忘。虽然 UDP 服务本质上拥有被忽视的趋势，这些服务可以枚举，用来完全理解任何给定目标的工具面，这相当关键。UDP 扫描通常由挑战性，麻烦，并且消耗时间。这一章的前三个秘籍会涉及如何在 Kali 中使用不同工具执行 UDP 扫描。理解 UDP 扫描可以用两种不同的方式执行相当重要。一种技巧会在第一个秘籍中强调，它仅仅依赖于 ICMP 端口不可达响应。这类型的扫描依赖于任何没有绑定某个服务的 UDP 端口都会返回 ICP 端口不可达响应的假设。所以不返回这种响应就代表拥有服务。虽然这种方法在某些情况下十分高效，在主机不生成端口不可达响应，或者端口不可达响应存在速率限制或被防火墙过滤的情况下，它也会返回不精确的结果。一种替代方式会在第二个和第三个秘籍中讲解，是使用服务特定的探针来尝试请求响应，以表明所预期的服务运行在目标端口上。这个方法非常高效，也非常消耗时间。

## 3.2 TCP 扫描

这一章中，会提及几个不同的 TCP 扫描方式。这些技巧包含隐秘扫描、连接扫描和僵尸扫描。为了理解这些扫描技巧的原理，理解 TCP 如何建立以及维护连接十分重要。TCP 是面向连接的协议，只有连接在两个系统之间建立之后，数据才可以通过 TCP 传输。这个和建立 TCP 连接的过程通常使用三次握手指代。这个内容暗指连接过程涉及的三个步骤。下图展示了这个过程：

![](img/3-2-1.jpg)

TCP SYN 封包从想要建立连接的设备发送，并带有想要连接的设备端口。如果和接收端口关联的服务接收了这个连接，它会向请求系统返回 TCP 封包，其中 SYN 和 ACK 位都是激活的。连接仅仅在请求系统发送 TCP ACK 响应的情况下建立。这个三步过程在两个系统之间建立了 TCP 会话。所有 TCP 端口扫描机制都会执行这个过程的不同变种，来识别远程主机上的活动服务。

连接扫描和隐秘扫描都非常易于理解。连接扫描会为每个扫描端口建立完整的 TCP 连接。这就是说，对于每个扫描的端口，会完成三次握手。如果连接成功建立，端口可以判断为打开的。作为替代，隐秘扫描不建立完整的连接。隐秘扫描也指代 SYN 扫描或半开放扫描。对于每个扫描的端口，指向目标端口发送单个 SYN 封包，所有回复 SYN+ACK 封包的端口假设为运行活动服务。由于初始系统没有发送最后的 ACK，连接只开启了左半边。这用于指代隐秘扫描，是因为日志系统只会记录建立的链接，不会记录任何这种扫描的痕迹。

这一章要讨论的最后一种 TCP 扫描技术叫做僵尸扫描。僵尸扫描的目的是映射远程系统上的所有开放端口，而不会产生任何和系统交互过的痕迹。僵尸扫描背后的工作原理十分复杂。执行僵尸扫描过程需要遵循以下步骤：

1.  将某个远程系统看做你的僵尸。这个系统应该拥有如下特征：

    +   这个系统是限制的，并且和网络上其它系统没有通信。
    +   这个系统使用递增的 IPID 序列。
    
2.  给僵尸主机发送 SYN+ACK 封包并记录初始 IPID 值。

3.  将封包的 IP 源地址伪造成僵尸主机的 IP 地址，并将其发送给目标系统。

4.  取决于扫描目标的端口状态，会发生下列事情之一：

    +   如果端口开放，扫描目标会向僵尸主机返回 SYN+ACK 封包，它相信僵尸主机发送了之前的 SYN 请求。这里，僵尸主机会以 RST 封包回复这个带路不明的 SYN+ACK 封包，并且将 IPID 值增加 1。
    +   如果端口关闭，扫描目标会将 RST 响应返回给僵尸主机，   它相信僵尸主机发送了之前的 SYN 请求。如果这个值增加了 1，那么之后扫描目标上的端口关闭，。如果这个值增加了 2，那么扫描目标的端口开放。
    
5.  向僵尸主机发送另一个 SYN+ACK 封包，并求出所返回的 RST 响应中的最后的 IPID 值。如果这个值增加了 1，那么扫描目标上的端口关闭。如果增加了 2，那么扫描目标上的端口开放。

下面的图展示了当僵尸主机用于扫描开放端口时，所产生的交互。

![](img/3-2-2.jpg)

为了执行僵尸扫描，初始的 SYN+SCK 请求应该发给僵尸系统来判断返回 RST 封包中的当前 IPID 值。之后，将伪造的 SYN 封包发往目标咪表，带有僵尸主机的源 IP 地址。如果端口开放，扫描目标会将 SYN+ACK 响应发回僵尸主机。由于将是主机并没有实际发送之前的 SYN 请求，它会将 SYN+ACK 响应看做来路不明，并将 RST 请求发送回目标主机，因此 IPID 会增加 1。最后，应该向僵尸主机发送另一个 SYN+ACK 封包，这会返回 RST 封包并再次增加 IPID。增加 2 的 IPID 表示所有这些事件都发生了，目标端口是开放的。反之，如果扫描目标的端口是关闭的，会发生一系列不同的事件，这会导致 RST 响应的 IPID 仅仅增加 1。

下面的图展示了当僵尸主机用于扫描关闭端口时，所产生的交互。

![](img/3-2-3.jpg)

如果目标端口关闭，发往僵尸系统的 RST 封包是之前伪造的 SYN 封包的响应。由于 RST 封包没有手造恢复，僵尸系统的 IPID 值不会增加。因此，返回给扫描系统的最后的 RST 封包的 IPID 值只会增加 1。这个过程可以对每个想要扫描的端口执行，它可以用于映射远程系统的开放端口，而不需要留下扫描系统执行了扫描的痕迹。

## 3.3 Scapy UDP 扫描 

Scapy 可以用于向网络构造和注入自定义封包。在这个秘籍中，Scapy 会用于扫描活动的 UDP 服务。这可以通过发送空的 UDP 封包给目标端口，之后识别没有回复 ICMP 不可达响应的端口来实现。

### 准备

为了使用 Scapy 执行 UDP 扫描，你需要一个运行 UDP 网络服务的远程服务器。这个例子中我们使用 Metasploitable2 实例来执行任务。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器*VIM 和 Nano）。

### 操作步骤

使用 Scapy，我们就可以快速理解 UDP 扫描原理背后的底层规则。为了确认任何给定端口上是否存在 UDP 服务，我们需要让服务器产生响应。这个证明十分困难，因为许多 UDP 服务都只回复服务特定的请求。任何特定服务的知识都会使正面识别该服务变得容易。但是，有一些通常技巧可以用于判断服务是否运行于给定的 UDP 端口，并且准确率还不错。我们将要使用 Scapy 操作的这种技巧是识别关闭的端口的 ICMP 不可达响应。为了向任何给定端口发送 UDP 请求，我们首先需要构建这个请求的一些层面，我们需要构建的第一层就是 IP 层。

```
root@KaliLinux:~# scapy 
Welcome to Scapy (2.2.0) 
>>> i = IP() 
>>> i.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= ip  
    chksum= None  
    src= 127.0.0.1  
    dst= 127.0.0.1  
    \options\ 
>>> i.dst = "172.16.36.135" 
>>> i.display()
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1
    flags=   
    frag= 0  
    ttl= 64  
    proto= ip  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\ 
```

为了构建请求的 IP 层，我们需要将`IP`对象赋给变量`i`。通过调用`display`函数，我们可以确定对象的属性配置。通常，发送和接受地址都设为回送地址，`127.0.0.1`。这些值可以通过修改目标地址来修改，也就是设置`i.dst`为想要扫描的地址的字符串值。通过再次调用`dislay`函数，我们看到不仅仅更新的目标地址，也自动更新了和默认接口相关的源 IP 地址。现在我们构建了请求的 IP 层，我们可以构建 UDP 层了。

```
>>> u = UDP() 
>>> u.display() 
###[ UDP ]###  
    sport= domain  
    dport= domain  
    len= None  
    chksum= None 
>>> u.dport 
53 
```

为了构建请求的 UDP 层，我们使用和 IP 层相同的技巧。在这个立即中，`UDP`对象赋给了`u`变量。像之前提到的那样，默认的配置可以通过调用`display`函数来确定。这里，我们可以看到来源和目标端口的默认值都是`domain`。你可能已经猜到了，它表示和端口 53 相关的 DNS 服务。DNS 是个常见服务，通常能在网络系统上发现。为了确认它，我们可以通过引用变量名称和数量直接调用该值。之后，可以通过将属性设置为新的目标端口值来修改。

```
>>> u.dport = 123 
>>> u.display() 
###[ UDP ]###
    sport= domain  
    dport= ntp  
    len= None  
    chksum= None 
```

在上面的例子中，目标端口设为`123`，这是 NTP 的端口。既然我们创建了 IP 和 UDP 层，我们需要通过叠放这些层来构造请求。

```
>>> request = (i/u) 
>>> request.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= udp  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\ 
###[ UDP ]###     
    sport= domain     
    dport= ntp     
    len= None     
    chksum= None
```

我们可以通过以斜杠分离变量来叠放 IP 和 UDP 层。这些层面之后赋给了新的变量，它代表整个请求。我们之后可以调用`dispaly`函数来查看请求的配置。一旦构建了请求，可以将其传递给`sr1`函数来分析响应：

```
>>> response = sr1(request) 
Begin emission: 
......Finished to send 1 packets. 
....*
Received 11 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###  
    version= 4L  
    ihl= 5L  
    tos= 0xc0  
    len= 56  
    id= 63687  
    flags=   
    frag= 0L  
    ttl= 64  
    proto= icmp  
    chksum= 0xdfe1  
    src= 172.16.36.135  
    dst= 172.16.36.180  
    \options\ 
###[ ICMP ]###     
    type= dest-unreach     
    code= port-unreachable     
    chksum= 0x9e72     
    unused= 0 
###[ IP in ICMP ]###        
    version= 4L        
    ihl= 5L        
    tos= 0x0        
    len= 28        
    id= 1        
    flags=         
    frag= 0L        
    ttl= 64        
    proto= udp        
    chksum= 0xd974        
    src= 172.16.36.180        
    dst= 172.16.36.135        
    \options\
###[ UDP in ICMP ]###           
    sport= domain           
    dport= ntp           
    len= 8           
    chksum= 0x5dd2 
```

相同的请求可以不通过构建和堆叠每一层来执行。反之，我们使用单独的一条命令，通过直接调用函数并传递合适的参数：

```
>>> sr1(IP(dst="172.16.36.135")/UDP(dport=123)) 
..Begin emission: 
...*Finished to send 1 packets.

Received 6 packets, got 1 answers, remaining 0 packets 
<IP  version=4L ihl=5L tos=0xc0 len=56 id=63689 flags= frag=0L ttl=64 proto=icmp chksum=0xdfdf src=172.16.36.135 dst=172.16.36.180 options=[] |<ICMP  type=dest-unreach code=port-unreachable chksum=0x9e72 unused=0 |<IPerror  version=4L ihl=5L tos=0x0 len=28 id=1 flags= frag=0L ttl=64 proto=udp chksum=0xd974 src=172.16.36.180 dst=172.16.36.135 options=[] |<UDPerror  sport=domain dport=ntp len=8 chksum=0x5dd2 |>>>>
```

要注意这些请求的响应包括 ICMP 封包，它的`type`表示主机不可达，它的`code`表示端口不可达。这个响应通常在 UDP 端口关闭时返回。现在，我们应该尝试修改请求，使其发送到对应远程系统上的真正服务的目标端口。为了实现它，我们将目标端口修改会`53`，之后再次发送请求，像这样：

```
>>> response = sr1(IP(dst="172.16.36.135")/UDP(dport=53),timeout=1,verbo se=1) 
Begin emission: 
Finished to send 1 packets.

Received 8 packets, got 0 answers, remaining 1 packets
```

当相同请求发送到真正的服务时，没有收到回复。这是因为 DNS 服务运行在系统的 UDP 端口 53 上，仅仅响应服务特定的请求。这一差异可以用于扫描 ICMP 不可达响应，我们可以通过扫描无响应的端口来确定潜在的服务：

```py
#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import * 
import time 
import sys

if len(sys.argv) != 4:   
    print "Usage - ./udp_scan.py [Target-IP] [First Port] [Last Port]"   
    print "Example - ./udp_scan.py 10.0.0.5 1 100"   
    print "Example will UDP port scan ports 1 through 100 on 10.0.0.5" 
sys.exit()

ip = sys.argv[1] 
start = int(sys.argv[2]) 
end = int(sys.argv[3])

for port in range(start,end):   
    ans = sr1(IP(dst=ip)/UDP(dport=port),timeout=5,verbose=0)   
    time.sleep(1)   
    if ans == None:      
        print port   
    else:      
        pass 
```

上面的 Python 脚本向序列中前一百个端口中的每个端口发送 UDP 请求。这里没有接受到任何响应，端口可以认为是开放的。通过运行这个脚本，我们可以识别所有不返回 ICMP 不可达响应的端口：

```
root@KaliLinux:~# chmod 777 udp_scan.py 
root@KaliLinux:~# ./udp_scan.py 
Usage - ./udp_scan.py [Target-IP] [First Port] [Last Port] 
Example - ./udp_scan.py 10.0.0.5 1 100 
Example will UDP port scan ports 1 through 100 on 10.0.0.5 
root@KaliLinux:~ # ./udp_scan.py 172.16.36.135 1 100 
53 
68 
69
```

超时为`5`秒用于接受受到 ICMP 不可达速率限制的响应。即使拥有了更大的响应接收窗口，这种方式的扫描仍然有时不可靠。这就是 UDP 探测扫描是更加高效的替代方案的原因。

### 工作原理

这个秘籍中，UDP 扫描通过识别不回复 ICMP 端口不可达响应的端口来识别。这个过程非常耗费时间，因为 ICMP 端口不可达响应通常有速率限制。有时候，对于不生成这种响应的系统，这种方式会不可靠，并且 ICMP 通常会被防火墙过滤。替代方式就是使用服务特定的探针来请求正面的响应。这个技巧会在下面的两个秘籍中展示。

## 3.4 Nmap UDP 扫描

Nmap 拥有可以执行远程系统上的 UDP 扫描的选项。Nmap 的 UDP 扫描方式更加复杂，它通过注入服务特定的谭泽请求，来请求正面的响应，用于确认指定服务的存在，来识别活动服务。这个秘籍演示了如何使用 Nmap UDP 扫描来扫描单一端口，多个端口，甚至多个系统。

### 准备

为了使用 Nmap 执行 UDP 扫描，你需要一个运行 UDP 网络服务的远程服务器。这个例子中我们使用 Metasploitable2 实例来执行任务。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

UDP 扫描通常由挑战性，消耗时间，非常麻烦。许多系统会限制 ICMp 主机不可达响应，并且增加扫描大量端口或系统所需的时间总数。幸运的是，Nmap 的开发者拥有更加复杂和高效的工具来识别远程系统上的 UDP 服务。为了使用 Nmap 执行 UDP 扫描，需要使用`-sU`选项，并带上需要扫描的主机 IP 地址。

```
root@KaliLinux:~# nmap -sU 172.16.36.135

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-17 21:04 EST
Nmap scan report for 172.16.36.135 
Host is up (0.0016s latency). 
Not shown: 993 closed ports 
PORT     STATE         SERVICE 
53/udp   open          domain
68/udp   open|filtered dhcpc 
69/udp   open|filtered tftp 
111/udp  open          rpcbind 
137/udp  open          netbios-ns 
138/udp  open|filtered netbios-dgm 
2049/udp open          nfs 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1043.91 seconds
```

虽然 Nmap 使用针对多种服务的自定义载荷来请求 UDP 端口的响应。在没有使用其它参数来指定目标端口时，它仍旧需要大量时间来扫描默认的 1000 个端口。你可以从扫描元数据中看到，默认的扫描需要将近 20 分钟来完成。作为替代，我们可以缩短所需的扫描时间，通过使用下列名Ingles执行针对性扫描：

```
root@KaliLinux:~# nmap 172.16.36.135 -sU -p 53


Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-17 21:05 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.0010s latency). 
PORT   STATE SERVICE 53/udp open  
domain MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 13.09 seconds 
```

如果我们指定了需要扫描的特定端口，执行 UDP 扫描所需的的时间总量可以极大江少。这可以通过执行 UDP 扫描并且使用`-p`选项指定端口来实现。在下面的例子中，我们仅仅在`53`端口上执行扫描，来尝试识别 DNS 服务。也可以在多个指定的端口上指定扫描，像这样：

```
root@KaliLinux:~# nmap 172.16.36.135 -sU -p 1-100

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-17 21:06 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00054s latency). 
Not shown: 85 open|filtered ports
PORT   STATE  SERVICE 
8/udp  closed unknown 
15/udp closed unknown 
28/udp closed unknown 
37/udp closed time 
45/udp closed mpm 
49/udp closed tacacs 
53/udp open   domain 
56/udp closed xns-auth 
70/udp closed gopher 
71/udp closed netrjs-1 
74/udp closed netrjs-4 
89/udp closed su-mit-tg 
90/udp closed dnsix 
95/udp closed supdup 
96/udp closed dixie 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 23.56 seconds 
```

在这个例子中，扫描在前 100 个端口上执行。这通过使用破折号符号，并指定要扫描的第一个和最后一个端口来完成。Nmap 之后启动多个进程，会同时扫描这两个值之间的多有端口。在一些情况下，UDP 分析需要在多个系统上执行。可以使用破折号符号，并且定义最后一个 IP 段的值的范围，来扫描范围内的主机。

```
root@KaliLinux:~# nmap 172.16.36.0-255 -sU -p 53

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-17 21:08 EST 
Nmap scan report for 172.16.36.1 
Host is up (0.00020s latency). 
PORT   STATE  SERVICE 
53/udp closed domain 
MAC Address: 00:50:56:C0:00:08 (VMware)

Nmap scan report for 172.16.36.2 
Host is up (0.039s latency).
PORT   STATE  SERVICE 
53/udp closed domain 
MAC Address: 00:50:56:FF:2A:8E (VMware)

Nmap scan report for 172.16.36.132 
Host is up (0.00065s latency). 
PORT   STATE  SERVICE 
53/udp closed domain 
MAC Address: 00:0C:29:65:FC:D2 (VMware)

Nmap scan report for 172.16.36.135 
Host is up (0.00028s latency). 
PORT   STATE SERVICE 
53/udp open  domain 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 256 IP addresses (6 hosts up) scanned in 42.81 seconds
```
这个例子中，扫描对`172.16.36.0/24 `中所有活动主机执行。每个主机都被扫描来识别是否在 53 端口上运行了 DNS 服务。另一个用于扫描多个主机替代选项，就是使用 IP 地址输入列表。为了这样做，使用`-iL`选项，并且应该传入相同目录下的文件名称，或者单独目录下的完成文件路径。前者的例子如下：

```
root@KaliLinux:~# nmap -iL iplist.txt -sU -p 123

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-17 21:16 EST 
Nmap scan report for 172.16.36.1 
Host is up (0.00017s latency). 
PORT    STATE SERVICE 
123/udp open  ntp 
MAC Address: 00:50:56:C0:00:08 (VMware)

Nmap scan report for 172.16.36.2 
Host is up (0.00025s latency). 
PORT    STATE         SERVICE 
123/udp open|filtered ntp
MAC Address: 00:50:56:FF:2A:8E (VMware)

Nmap scan report for 172.16.36.132 
Host is up (0.00040s latency). 
PORT    STATE  SERVICE 
123/udp closed ntp 
MAC Address: 00:0C:29:65:FC:D2 (VMware)

Nmap scan report for 172.16.36.135 
Host is up (0.00031s latency). 
PORT    STATE  SERVICE 
123/udp closed ntp 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 4 IP addresses (4 hosts up) scanned in 13.27 seconds
```

这个例子中，执行了扫描来判断 NTP 服务是否运行在当前执行目录中的`iplist.txt `文件内的任何系统的 123 端口上。

### 工作原理

虽然 Nmap 仍然含有许多和 UDP 扫描相关的相同挑战，它仍旧是个极其高效的解决方案，因为它使用最高效和快速的技巧组合来识别活动服务。

## 3.5 Metasploit UDP 扫描

Metasploit 拥有一个辅助模块，可以用于扫描特定的常用 UDP 端口。这个秘籍展示了如何使用这个辅助模块来扫描运行 UDP 服务的单个系统或多个系统。

### 准备

为了使用 Metasploit 执行 UDP 扫描，你需要一个运行 UDP 网络服务的远程服务器。这个例子中我们使用 Metasploitable2 实例来执行任务。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

在定义所运行的模块之前，需要打开 Metasploit。为了在 Kali 中打开它，我们在终端会话中执行`msfconsole`命令。

```
root@KaliLinux:~# msfconsole 
# cowsay++
 ____________
 < metasploit >
 -----------
        \   ,__,       
         \  (oo)____           
            (__)    )\           
               ||--|| *

Large pentest? List, sort, group, tag and search your hosts and services in Metasploit Pro -- type 'go_pro' to launch it now.
       
       =[ metasploit v4.6.0-dev [core:4.6 api:1.0] 
+ -- --=[ 1053 exploits - 590 auxiliary - 174 post 
+ -- --=[ 275 payloads - 28 encoders - 8 nops

msf > use auxiliary/scanner/discovery/udp_sweep 
msf  auxiliary(udp_sweep) > show options

Module options (auxiliary/scanner/discovery/udp_sweep):
   
    Name       Current Setting  Required  Description   
    ----       ---------------  --------  ----------   
    BATCHSIZE  256              yes       The number of hosts to probe in each set   
    CHOST                       no        The local client address   
    RHOSTS                      yes       The target address range or CIDR identifier   
    THREADS    1                yes       The number of concurrent threads
```

为了在 Metasploit 中运行 UDP 扫描模块，我们以模块的相对路径调用`use`命令。一旦选择了模块，可以使用`show options`命令来确认或更改扫描配置。这个命令会展示四个列的表格，包括`name`、`current settings`、`required`和`description`。`name`列标出了每个可配置变量的名称。`current settings`列列出了任何给定变量的现有配置。`required`列标出对于任何给定变量，值是否是必须的。`description`列描述了每个变量的功能。任何给定变量的值可以使用`set`命令，并且将新的值作为参数来修改。

```
msf  auxiliary(udp_sweep) > set RHOSTS 172.16.36.135 
RHOSTS => 172.16.36.135 
msf  auxiliary(udp_sweep) > set THREADS 20 
THREADS => 20 
msf  auxiliary(udp_sweep) > show options

Module options (auxiliary/scanner/discovery/udp_sweep):

    Name       Current Setting  Required  Description   
    ----       ---------------  --------  ----------   
    BATCHSIZE  256              yes       The number of hosts to probe in each set   
    CHOST                       no        The local client address   
    RHOSTS     172.16.36.135    yes       The target address range or CIDR identifier   
    THREADS    20               yes       The number of concurrent threads
```

在上面的例子中，`RHOSTS`值修改为我们打算扫描的远程系统的 IP 地址。地外，线程数量修改为 20。`THREADS`的值定位了在后台执行的当前任务数量。确定线程数量涉及到寻找一个平衡，既能提升任务速度，又不会过度消耗系统资源。对于多数系统，20 个线程可以足够快，并且相当合理。修改了必要的变量之后，可以再次使用`show options`命令来验证。一旦所需配置验证完毕，就可以执行扫描了。

```
msf  auxiliary(udp_sweep) > run

[*] Sending 12 probes to 172.16.36.135->172.16.36.135 (1 hosts) 
[*] Discovered Portmap on 172.16.36.135:111 (100000 v2 TCP(111), 100000 v2 UDP(111), 100024 v1 UDP(36429), 100024 v1 TCP(56375), 100003 v2 UDP(2049), 100003 v3 UDP(2049), 100003 v4 UDP(2049), 100021 v1 UDP(34241), 100021 v3 UDP(34241), 100021 v4 UDP(34241), 100003 v2 TCP(2049), 100003 v3 TCP(2049), 100003 v4 TCP(2049), 100021 v1 TCP(50333), 100021 v3 TCP(50333), 100021 v4 TCP(50333), 100005 v1 UDP(47083), 100005 v1 TCP(57385), 100005 v2 UDP(47083), 100005 v2 TCP(57385), 100005 v3 UDP(47083), 100005 v3 TCP(57385)) 
[*] Discovered NetBIOS on 172.16.36.135:137 (METASPLOITABLE:<00>:U :METASPLOITABLE:<03>:U :METASPLOITABLE:<20>:U :__MSBROWSE__:<01>:G :WORKGROUP:<00>:G :WORKGROUP:<1d>:U :WORKGROUP:<1e>:G :00:00:00:00:00:00) 
[*] Discovered DNS on 172.16.36.135:53 (BIND 9.4.2) 
[*] Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed
```

Metasploit 中所使用的`run`命令用于执行所选的辅助模块。在上面的例子中，`run`命令对指定的 IP 地址执行 UDP 扫描。`udp_sweep`模块也可以使用破折号符号，对地址序列执行扫描。

```
msf  auxiliary(udp_sweep) > set RHOSTS 172.16.36.1-10 
RHOSTS => 172.16.36.1-10 
msf  auxiliary(udp_sweep) > show options

Module options (auxiliary/scanner/discovery/udp_sweep):

    Name       Current Setting  Required  Description   
    ----       ---------------  --------  ----------   
    BATCHSIZE  256              yes       The number of hosts to probe in each set   
    CHOST                       no        The local client address   
    RHOSTS     172.16.36.1-10   yes       The target address range or CIDR identifier   
    THREADS    20               yes       The number of concurrent threads

msf  auxiliary(udp_sweep) > run

[*] Sending 12 probes to 172.16.36.1->172.16.36.10 (10 hosts) 
[*] Discovered NetBIOS on 172.16.36.1:137 (MACBOOKPRO-3E0F:<00>:U :00:50:56:c0:00:08) 
[*] Discovered NTP on 172.16.36.1:123 (NTP v4 (unsynchronized)) 
[*] Discovered DNS on 172.16.36.2:53 (BIND 9.3.6-P1-RedHat-9.3.6-20. P1.el5_8.6)
[*] Scanned 10 of 10 hosts (100% complete) 
[*] Auxiliary module execution completed
```

在上面的例子中，UDP 扫描对 10 个主机地址执行，它们由`RHOSTS`变量指定。与之相似，`RHOSTS`可以使用`CIDR`记法来定义网络范围，像这样：

```
msf  auxiliary(udp_sweep) > set RHOSTS 172.16.36.0/24 
RHOSTS => 172.16.36.0/24 
msf  auxiliary(udp_sweep) > show options

Module options (auxiliary/scanner/discovery/udp_sweep):

   Name       Current Setting  Required  Description   
   ----       ---------------  --------  ----------   
   BATCHSIZE  256              yes       The number of hosts to probe in each set   
   CHOST                       no        The local client address   
   RHOSTS     172.16.36.0/24   yes       The target address range or CIDR identifier   
   THREADS    20               yes       The number of concurrent threads

msf  auxiliary(udp_sweep) > run

[*] Sending 12 probes to 172.16.36.0->172.16.36.255 (256 hosts) 
[*] Discovered Portmap on 172.16.36.135:111 (100000 v2 TCP(111), 100000 v2 UDP(111), 100024 v1 UDP(36429), 100024 v1 TCP(56375), 100003 v2 UDP(2049), 100003 v3 UDP(2049), 100003 v4 UDP(2049), 100021 v1 UDP(34241), 100021 v3 UDP(34241), 100021 v4 UDP(34241), 100003 v2 TCP(2049), 100003 v3 TCP(2049), 100003 v4 TCP(2049), 100021 v1 TCP(50333), 100021 v3 TCP(50333), 100021 v4 TCP(50333), 100005 v1 UDP(47083), 100005 v1 TCP(57385), 100005 v2 UDP(47083), 100005 v2 TCP(57385), 100005 v3 UDP(47083), 100005 v3 TCP(57385)) 
[*] Discovered NetBIOS on 172.16.36.135:137 (METASPLOITABLE:<00>:U :METASPLOITABLE:<03>:U :METASPLOITABLE:<20>:U :__MSBROWSE__:<01>:G :WORKGROUP:<00>:G :WORKGROUP:<1d>:U :WORKGROUP:<1e>:G :00:00:00:00:00:00) 
[*] Discovered NTP on 172.16.36.1:123 (NTP v4 (unsynchronized)) 
[*] Discovered NetBIOS on 172.16.36.1:137 (MACBOOKPRO-3E0F:<00>:U :00:50:56:c0:00:08) [*] Discovered DNS on 172.16.36.0:53 (BIND 9.3.6-P1-RedHat-9.3.6-20. P1.el5_8.6)

[*] Discovered DNS on 172.16.36.2:53 (BIND 9.3.6-P1-RedHat-9.3.6-20. P1.el5_8.6) 
[*] Discovered DNS on 172.16.36.135:53 (BIND 9.4.2) 
[*] Discovered DNS on 172.16.36.255:53 (BIND 9.3.6-P1-RedHat-9.3.6-20. P1.el5_8.6) 
[*] Scanned 256 of 256 hosts (100% complete) 
[*] Auxiliary module execution completed
```

### 工作原理

Metasploit 辅助模块中的 UDP 扫描比起 Nmap 更加简单。它仅仅针对有限的服务数量，但是在识别端口上的活动服务方面更加高效，并且比其它可用的 UDP 扫描器更快。

## 3.6 Scapy 隐秘扫描

执行 TCP 端口扫描的一种方式就是执行一部分。目标端口上的 TCP 三次握手用于识别端口是否接受连接。这一类型的扫描指代隐秘扫描， SYN 扫描，或者半开放扫描。这个秘籍演示了如何使用 Scapy 执行 TCP 隐秘扫描。

### 准备

为了使用 Scapy 执行 TCP 隐秘 扫描，你需要一个运行 TCP 网络服务的远程服务器。这个例子中我们使用 Metasploitable2 实例来执行任务。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器*VIM 和 Nano）。

### 操作步骤

为了展示如何执行 SYN 扫描，我们需要使用 Scapy 构造 TCP SYN 请求，并识别和开放端口、关闭端口以及无响应系统有关的响应。为了向给定端口发送 TCP SYN 请求，我们首先需要构建请求的各个层面。我们需要构建的第一层就是 IP 层：

```
root@KaliLinux:~# scapy 
Welcome to Scapy (2.2.0) 
>>> i = IP() 
>>> i.display()
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= ip  
    chksum= None  
    src= 127.0.0.1  
    dst= 127.0.0.1  
    \options\ 
>>> i.dst = "172.16.36.135" 
>>> i.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= ip  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\
```

为了构建请求的 IP 层，我们需要将`IP`对象赋给变量`i`。通过调用`display`函数，我们可以确定对象的属性配置。通常，发送和接受地址都设为回送地址，`127.0.0.1`。这些值可以通过修改目标地址来修改，也就是设置`i.dst`为想要扫描的地址的字符串值。通过再次调用`dislay`函数，我们看到不仅仅更新的目标地址，也自动更新了和默认接口相关的源 IP 地址。现在我们构建了请求的 IP 层，我们可以构建 TCP 层了。

```
>>> t = TCP() 
>>> t.display() 
###[ TCP ]###  
    sport= ftp_data  
    dport= http  
    seq= 0  
    ack= 0  
    dataofs= None  
    reserved= 0  
    flags= S  
    window= 8192  
    chksum= None  
    urgptr= 0  
    options= {}
```

为了构建请求的 TCP 层，我们使用和 IP 层相同的技巧。在这个立即中，`TCP`对象赋给了`t`变量。像之前提到的那样，默认的配置可以通过调用`display`函数来确定。这里我们可以看到目标端口的默认值为 HTTP 端口 80。对于我们的首次扫描，我们将 TCP 设置保留默认。现在我们创建了 TCP 和 IP 层，我们需要将它们叠放来构造请求。

```
>>> request = (i/t) 
>>> request.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1
    flags=   
    frag= 0  
    ttl= 64  
    proto= tcp  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\ 
###[ TCP ]###     
    sport= ftp_data     
    dport= http     
    seq= 0     
    ack= 0     
    dataofs= None     
    reserved= 0     
    flags= S     
    window= 8192     
    chksum= None     
    urgptr= 0     
    options= {}
```

我们可以通过以斜杠分离变量来叠放 IP 和 TCP 层。这些层面之后赋给了新的变量，它代表整个请求。我们之后可以调用`dispaly`函数来查看请求的配置。一旦构建了请求，可以将其传递给`sr1`函数来分析响应：

```
>>> response = sr1(request) 
...Begin emission: 
........Finished to send 1 packets. 
....* 
Received 16 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###  
    version= 4L  
    ihl= 5L  
    tos= 0x0  
    len= 44
    id= 0  
    flags= DF  
    frag= 0L  
    ttl= 64  
    proto= tcp  
    chksum= 0x9970  
    src= 172.16.36.135  
    dst= 172.16.36.180  
    \options\ 
###[ TCP ]###     
    sport= http     
    dport= ftp_data     
    seq= 2848210323L     
    ack= 1     
    dataofs= 6L     
    reserved= 0L     
    flags= SA     
    window= 5840     
    chksum= 0xf82d     
    urgptr= 0     
    options= [('MSS', 1460)] 
###[ Padding ]###        
    load= '\x00\x00'
```

相同的请求可以不通过构建和堆叠每一层来执行。反之，我们使用单独的一条命令，通过直接调用函数并传递合适的参数：

```
>>> sr1(IP(dst="172.16.36.135")/TCP(dport=80)) 
.Begin emission: .............Finished to send 1 packets. 
....* 
Received 19 packets, got 1 answers, remaining 0 packets 
<IP  version=4L ihl=5L tos=0x0 len=44 id=0 flags=DF frag=0L ttl=64 proto=tcp chksum=0x9970 src=172.16.36.135 dst=172.16.36.180 options=[] |<TCP  sport=http dport=ftp_data seq=542529227 ack=1 dataofs=6L reserved=0L flags=SA window=5840 chksum=0x6864 urgptr=0 options=[('MSS', 1460)] |<Padding  load='\x00\x00' |>>>
```

要注意当 SYN 封包发往目标 Web 服务器的 TCP 端口 80，并且该端口上运行了 HTTP 服务时，响应中会带有 TCP 标识 SA 的值，这表明 SYN 和 ACK 标识都被激活。这个响应表明特定的目标端口是开放的，并接受连接。如果相同类型的封包发往不接受连接的端口，会收到不同的请求。

```
>>> response = sr1(IP(dst="172.16.36.135")/TCP(dport=4444)) 
..Begin emission: 
.Finished to send 1 packets. 
...* Received 7 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###  
    version= 4L  
    ihl= 5L  
    tos= 0x0  
    len= 40  
    id= 0  
    flags= DF  
    frag= 0L 
    ttl= 64  
    proto= tcp 
    chksum= 0x9974 
    src= 172.16.36.135 
    dst= 172.16.36.180 
    \options\ 
###[ TCP ]###  
    sport= 4444    
    dport= ftp_data 
    seq= 0   
    ack= 1   
    dataofs= 5L  
    reserved= 0L  
    flags= RA  
    window= 0    
    chksum= 0xfd03   
    urgptr= 0
    options= {} 
###[ Padding ]###   
    load= '\x00\x00\x00\x00\x00\x00'
```

当 SYN 请求发送给关闭的端口时，返回的响应中带有 TCP 标识 RA，这表明 RST 和 ACK 标识为都被激活。ACK 为仅仅用于承认请求被接受，RST 为用于断开连接，因为端口不接受连接。作为替代，如果 SYN 封包发往崩溃的系统，或者防火墙过滤了这个请求，就可能接受不到任何信息。由于这个原因，在`sr1 `函数在脚本中使用时，应该始终使用`timeout`选项，来确保脚本不会在无响应的主机上挂起。

```
>>> response = sr1(IP(dst="172.16.36.136")/TCP(dport=4444),timeout=1,verb ose=1) 
Begin emission: 
Finished to send 1 packets

Received 15 packets, got 0 answers, remaining 1 packets 
```

如果函数对无响应的主机使用时，`timeout`值没有指定，函数会无限继续下去。这个演示中，`timout`值为 1秒，用于使这个函数更加完备，响应的值可以用于判断是否收到了响应：

```
root@KaliLinux:~# 
python Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information. 
>>> from scapy.all import * 
>>> response = sr1(IP(dst="172.16.36.136")/TCP(dport=4444),timeout=1,verb ose=1) 
Begin emission: 
WARNING: Mac address to reach destination not found. Using broadcast. Finished to send 1 packets.

Received 15 packets, got 0 answers, remaining 1 packets 
>>> if response == None: 
...     print "No Response!!!" 
... 
No Response!!!
```

Python 的使用使其更易于测试变量来识别`sr1`函数是否对其复制。这可以用作初步检验，来判断是否接收到了任何响应。对于接收到的响应，可以执行一系列后续检查来判断响应表明端口开放还是关闭。这些东西可以轻易使用 Python 脚本来完成，像这样：

```py
#!/usr/bin/python

import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import * 
import sys

if len(sys.argv) != 4:   
    print "Usage - ./syn_scan.py [Target-IP] [First Port] [Last Port]"   
    print "Example - ./syn_scan.py 10.0.0.5 1 100"   
    print "Example will TCP SYN scan ports 1 through 100 on 10.0.0.5"   
    sys.exit()

ip = sys.argv[1] 
start = int(sys.argv[2]) 
end = int(sys.argv[3])

for port in range(start,end):   
    ans = sr1(IP(dst=ip)/TCP(dport=port),timeout=1,verbose=0)   
    if ans == None:      
        pass   
    else:      
        if int(ans[TCP].flags) == 18:    
            print port  
        else:       
            pass 
```

在这个 Python 脚本中，用于被提示来输入 IP 地址，脚本之后会对定义好的端口序列执行 SYN 扫描。脚本之后会得到每个连接的响应，并尝试判断响应的 SYN 和 ACK 标识是否激活。如果响应中出现并仅仅出现了这些标识，那么会输出相应的端口号码。

```
root@KaliLinux:~# chmod 777 syn_scan.py 
root@KaliLinux:~# ./syn_scan.py 
Usage - ./syn_scan.py [Target-IP] [First Port] [Last Port] 
Example - ./syn_scan.py 10.0.0.5 1 100 
Example will TCP SYN scan ports 1 through 100 on 10.0.0.5 
root@KaliLinux:~# ./syn_scan.py 172.16.36.135 1 100

21 
22 
23 
25 
53 
80 
```

运行这个脚本之后，输出会显示所提供的 IP 地址的系统上，前 100 个端口中的开放端口。

### 工作原理

这一类型的扫描由发送初始 SYN 封包给远程系统的目标 TCP 端口，并且通过返回的响应类型来判断端口状态来完成。如果远程系统返回了 SYN+ACK 响应，那么它正在准备建立连接，我们可以假设这个端口开放。如果服务返回了 RST 封包，这就表明端口关闭并且不接收连接。此外，如果没有返回响应，扫描系统和远程系统之间可能存在防火墙，它丢弃了请求。这也可能表明主机崩溃或者目标 IP 上没有关联任何系统。
