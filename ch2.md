# 第二章 探索扫描

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 2.2 使用 ARPing 探索第二层

ARPing 是一个命令行网络工具，具有类似于常用的`ping`工具的功能。 此工具可通过提供该 IP 地址作为参数，来识别活动主机是否位于给定 IP 的本地网络上。 这个秘籍将讨论如何使用 ARPing 扫描网络上的活动主机。

### 准备

要使用 ARPing 执行 ARP 发现，你将需要在 LAN 上至少拥有一个响应 ARP 请求的系统。 提供的示例使用 Linux 和 Windows 系统的组合。 有关在本地实验环境中设置系统的更多信息，请参阅第一章入中的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅第一章入门中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

ARPing是一种工具，可用于发送 ARP 请求并标识主机是否活动和响应。 该工具仅通过将 IP 地址作为参数传递给它来使用：

```
root@KaliLinux:~# arping 172.16.36.135 -c 1 
ARPING 172.16.36.135 
60 bytes from 00:0c:29:3d:84:32 (172.16.36.135): index=0 time=249.000 usec

--- 172.16.36.135 statistics --
1 packets transmitted, 1 packets received,   0% unanswered (0 extra) 
```

在所提供的示例中，单个 ARP 请求被发送给广播地址，请求`172.16.36.135` IP 地址的物理位置。 如输出所示，主机从`00：0C：29：3D：84：32 ` MAC地址接收到单个应答。 此工具可以更有效地用于第二层上的发现，扫描是否使用 bash 脚本在多个主机上同时执行此操作。 为了测试 bash 中每个实例的响应，我们应该确定响应中包含的唯一字符串，它标识了活动主机，但不包括没有收到响应时的情况。 要识别唯一字符串，应该对无响应的 IP 地址进行 ARPing 请求：

```
root@KaliLinux:~# arping 172.16.36.136 -c 1 
ARPING 172.16.36.136

--- 172.16.36.136 statistics --
1 packets transmitted, 0 packets received, 100% unanswered (0 extra)

```

通过分析来自成功和失败的不同 ARP 响应，你可能注意到，如果存在所提供的 IP 地址的相关活动主机，并且它也在包含在 IP 地址的行内，则响应中存在来自字符串的唯一字节。 通过对此响应执行`grep`，我们可以提取每个响应主机的 IP 地址：

```
root@KaliLinux:~# arping -c 1 172.16.36.135 | grep "bytes from" 
60 bytes from 00:0c:29:3d:84:32 (172.16.36.135): index=0 time=10.000 usec 
root@KaliLinux:~# arping -c 1 172.16.36.135 | grep "bytes from" | cut -d " " -f 4 
00:0c:29:3d:84:32
```

我们可以仅仅通过处理提供给`cut`函数的分隔符和字段值，从返回的字符串中轻松地提取 IP 地址：

```
root@KaliLinux:~# arping -c 1 172.16.36.135 | grep "bytes from" 
60 bytes from 00:0c:29:3d:84:32 (172.16.36.135): index=0 time=328.000 usec 
root@KaliLinux:~# arping -c 1 172.16.36.135 | grep "bytes from" | cut -d " " -f 5 (172.16.36.135): 
root@KaliLinux:~# arping -c 1 172.16.36.135 | grep "bytes from" | cut -d " " -f 5 | cut -d "(" -f 2 172.16.36.135): 
root@KaliLinux:~# arping -c 1 172.16.36.135 | grep "bytes from" | cut -d " " -f 5 | cut -d "(" -f 2 | cut -d ")" -f 1 
172.16.36.135

```

在识别如何从正面 ARPing 响应中提取 IP 在 bash 脚本中轻易将该任务传递给循环，并输出实时 IP 地址列表。 使用此技术的脚本的示例如下所示：

```sh
#!/bin/bash

if [ "$#" -ne 1 ]; then 
    echo "Usage - ./arping.sh [interface]" 
    echo "Example - ./arping.sh eth0" 
    echo "Example will perform an ARP scan of the local subnet to which eth0 is assigned" 
    exit 
fi

interface=$1 
prefix=$(ifconfig $interface | grep 'inet addr' | 
cut -d ':' -f 2 | cut -d ' ' -f 1 | cut -d '.' -f 1-3)

for addr in $(seq 1 254); do 
    arping -c 1 $prefix.$addr | grep "bytes from" | cut -d " " -f 5 | cut -d "(" -f 2 | cut -d ")" -f 1 & 
done 
```

在提供的 bash 脚本中，第一行定义了 bash 解释器的位置。接下来的代码块执行测试，来确定是否提供了预期的参数。这通过评估提供的参数的数量是否不等于 1 来确定。如果未提供预期参数，则输出脚本的用法，并且退出脚本。用法输出表明，脚本预期将本地接口名称作为参数。下一个代码块将提供的参数赋给`interface `变量。然后将接口值提供给`ifconfig`，然后使用输出提取网络前缀。例如，如果提供的接口的 IP 地址是`192.168.11.4`，则前缀变量将赋为`192.168.11`。然后使用`for`循环遍历最后一个字节的值，来在本地`/ 24`网络中生成每个可能的 IP 地址。对于每个可能的 IP 地址，执行单个`arping`命令。然后对每个请求的响应通过管道进行传递，然后使用`grep`来提取带有短语`bytes`的行。如前所述，这只会提取包含活动主机的 IP 地址的行。最后，使用一系列`cut`函数从此输出中提取 IP 地址。请注意，在`for`循环任务的末尾使用`&`符号，而不是分号。符号允许并行执行任务，而不是按顺序执行。这极大地减少了扫描 IP 范围所需的时间。看看下面的命令集：

```
root@KaliLinux:~# ./arping.sh 
Usage - ./arping.sh [interface] 
Example - ./arping.sh eth0 
Example will perform an ARP scan of the local subnet to which eth0 is assigned

root@KaliLinux:~# ./arping.sh eth0 
172.16.36.1 
172.16.36.2 
172.16.36.132 
172.16.36.135 
172.16.36.254 
```

可以轻易将脚本的输出重定向到文本文件，然后用于随后的分析。 可以使用尖括号重定向输出，后跟文本文件的名称。 一个例子如下：

```
root@KaliLinux:~# ./arping.sh eth0 > output.txt 
root@KaliLinux:~# ls output.txt 
output.txt 
root@KaliLinux:~# cat output.txt 
172.16.36.1 
172.16.36.2 
172.16.36.132 
172.16.36.135 
172.16.36.254 
```

一旦输出重定向到输出文件，你就可以使用`ls`命令验证文件是否已写入文件系统，或者可以使用`cat`命令查看文件的内容。 此脚本还可以修改为从输入文件读取，并仅验证此文件中列出的主机是否处于活动状态。 对于以下脚本，你需要拥有 IP 地址列表的输入文件。 为此，我们可以使用与上一个秘籍中讨论的 Scapy 脚本所使用的相同的输入文件：

```sh
#!/bin/bash
if [ "$#" -ne 1 ]; then 
    echo "Usage - ./arping.sh [input file]" 
    echo "Example - ./arping.sh iplist.txt" 
    echo "Example will perform an ARP scan of all IP addresses defined in iplist.txt" 
    exit 
fi

file=$1

for addr in $(cat $file); do 
    arping -c 1 $addr | grep "bytes from" | cut -d " " -f 5 | cut -d "(" -f 2 | cut -d ")" -f 1 & 
done

```

这个脚本和前一个脚本唯一的主要区别是，并没有提供一个接口名，而是在执行脚本时提供输入列表的文件名。 这个参数被传递给文件变量。 然后，`for`循环用于循环遍历此文件中的每个值，来执行 ARPing 任务。 为了执行脚本，请使用句号和斜杠，后跟可执行脚本的名称：

```
root@KaliLinux:~# ./arping.sh 
Usage - ./arping.sh [input file] 
Example - ./arping.sh iplist.txt 
Example will perform an ARP scan of all IP addresses defined in iplist.txt 
root@KaliLinux:~# ./arping.sh iplist.txt 
172.16.36.1 
172.16.36.2 
172.16.36.132 
172.16.36.135 
172.16.36.254
```

在没有提供任何参数的情况下执行脚本将返回脚本的用法。 此用法表示，应提供输入文件作为参数。 此操作完成后将执行脚本，并从输入的 IP 地址列表返回实时 IP 地址列表。 使用与前面讨论的相同的方式，此脚本的输出可以通过尖括号轻易重定向到输出文件。 一个例子如下：

```
root@KaliLinux:~# ./arping.sh iplist.txt > output.txt 
root@KaliLinux:~# ls output.txt 
output.txt 
root@KaliLinux:~# cat output.txt 
172.16.36.1 
172.16.36.2 
172.16.36.132 
172.16.36.135 
172.16.36.254 
```

一旦输出重定向到输出文件，你可以使用`ls`命令验证文件是否已写入文件系统，或者可以使用`cat`命令查看文件的内容。

### 工作原理

ARPing 是一个工具，用于验证单个主机是否在线。 然而，它的简单用法的使我们很容易操作它在 bash 中按顺序扫描多个主机。 这是通过循环遍历一系列 IP 地址，然后将这些 IP 地址作为参数提供给工具来完成的。

## 2.3 使用 Nmap 探索第二层

网络映射器（Nmap）是 Kali Linux 中最有效和强大的工具之一。 Nmap 可以用于执行大范围的多种扫描技术，并且可高度定制。 这个工具在整本书中会经常使用。 在这个特定的秘籍中，我们将讨论如何使用 Nmap 执行第2层扫描。

### 准备

要使用 ARPing 执行 ARP 发现，你将需要在 LAN 上至少拥有一个响应 ARP 请求的系统。 提供的示例使用 Linux 和 Windows 系统的组合。 有关在本地实验环境中设置系统的更多信息，请参阅第一章入中的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

### 操作步骤

Nmap 是使用单个命令执行自动化第二层发现扫描的另一个方案。 `-sn`选项在 Nmap 中称为`ping`扫描。 虽然术语“ping 扫描”自然会导致你认为正在执行第三层发现，但实际上是自适应的。 假设将同一本地子网上的地址指定为参数，可以使用以下命令执行第2层扫描：

```
root@KaliLinux:~# nmap 172.16.36.135 -sn
Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-16 15:40 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00038s latency). 
MAC Address: 00:0C:29:3D:84:32 (VMware) 

Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds 
```

此命令向 LAN 广播地址发送 ARP 请求，并根据接收到的响应确定主机是否处于活动状态。 或者，如果对不活动主机的 IP 地址使用该命令，则响应会表示主机关闭：

```
root@KaliLinux:~# nmap 172.16.36.136 -sn
Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-16 15:51 EST 
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn 

Nmap done: 1 IP address (0 hosts up) scanned in 0.41 seconds
```

我们可以修改此命令，来使用破折号符号对一系列顺序 IP 地址执行第2层发现。 要扫描完整的`/ 24`范围，可以使用`0-255`：

```
root@KaliLinux:~# nmap 172.16.36.0-255 -sn
Starting 
Nmap 6.25 ( http://nmap.org ) at 2013-12-11 05:35 EST 
Nmap scan report for 172.16.36.1 
Host is up (0.00027s latency). 
MAC Address: 00:50:56:C0:00:08 (VMware) 
Nmap scan report for 172.16.36.2 
Host is up (0.00032s latency). 
MAC Address: 00:50:56:FF:2A:8E (VMware) 
Nmap scan report for 172.16.36.132 
Host is up. 
Nmap scan report for 172.16.36.135 
Host is up (0.00051s latency). 
MAC Address: 00:0C:29:3D:84:32 (VMware) 
Nmap scan report for 172.16.36.200 
Host is up (0.00026s latency). 
MAC Address: 00:0C:29:23:71:62 (VMware) 
Nmap scan report for 172.16.36.254 
Host is up (0.00015s latency). 
MAC Address: 00:50:56:EA:54:3A (VMware) 

Nmap done: 256 IP addresses (6 hosts up) scanned in 3.22 seconds 
```

使用此命令将向该范围内的所有主机发送广播 ARP 请求，并确定每个主动响应的主机。 也可以使用`-iL`选项对 IP 地址的输入列表执行此扫描：

```
root@KaliLinux:~# nmap -iL iplist.txt -sn

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-16 16:07 EST 
Nmap scan report for 172.16.36.2 
Host is up (0.00026s latency). 
MAC Address: 00:50:56:FF:2A:8E (VMware) 
Nmap scan report for 172.16.36.1

Host is up (0.00021s latency). 
MAC Address: 00:50:56:C0:00:08 (VMware) 
Nmap scan report for 172.16.36.132 
Host is up (0.00031s latency). 
MAC Address: 00:0C:29:65:FC:D2 (VMware) 
Nmap scan report for 172.16.36.135 
Host is up (0.00014s latency). 
MAC Address: 00:0C:29:3D:84:32 (VMware) 
Nmap scan report for 172.16.36.180 
Host is up. 
Nmap scan report for 172.16.36.254 
Host is up (0.00024s latency). 
MAC Address: 00:50:56:EF:B9:9C (VMware) 

Nmap done: 8 IP addresses (6 hosts up) scanned in 0.41 seconds
```

当使用`-sn`选项时，Nmap 将首先尝试使用第2层 ARP 请求定位主机，并且如果主机不位于 LAN 上，它将仅使用第3层 ICMP 请求。 注意对本地网络（在`172.16.36.0/24`专用范围）上的主机执行的 Nmap ping 扫描才能返回 MAC 地址。 这是因为 MAC 地址由来自主机的 ARP 响应返回。 但是，如果对不同 LAN 上的远程主机执行相同的 Nmap ping 扫描，则响应不会包括系统的 MAC 地址。


```
root@KaliLinux:~# nmap -sn 74.125.21.0-255
Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-11 05:42 EST 
Nmap scan report for 74.125.21.0 
Host is up (0.0024s latency). 
Nmap scan report for 74.125.21.1 
Host is up (0.00017s latency). 
Nmap scan report for 74.125.21.2 
Host is up (0.00028s latency). 
Nmap scan report for 74.125.21.3 
Host is up (0.00017s latency).
```

当对远程网络范围（公共范围`74.125.21.0/24`）执行时，你可以看到，使用了第三层发现，因为没有返回 MAC 地址。 这表明，Nmap 会尽可能自动利用第二层发现的速度，但在必要时，它将使用可路由的 ICMP 请求，在第三层上发现远程主机。如果你使用 Wireshark 监控流量，而 Nmap 对本地网络上的主机执行 ping 扫描。 在以下屏幕截图中，你可以看到 Nmap 利用 ARP 请求来识别本地段范围内的主机：

![](img/2-3-1.jpg)

### 工作原理

Nmap 已经高度功能化，需要很少甚至无需调整就可以运行所需的扫描。 底层的原理是一样的。 Nmap 将 ARP 请求发送到一系列 IP 地址的广播地址，并通过标记响应来识别活动主机。 但是，由于此功能已集成到 Nmap 中，因此可以通过提供适当的参数来执行。
