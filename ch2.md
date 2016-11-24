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
