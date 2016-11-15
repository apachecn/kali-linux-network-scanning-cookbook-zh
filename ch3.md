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

## 3.3 使用 Scapy 扫描 UDP

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
