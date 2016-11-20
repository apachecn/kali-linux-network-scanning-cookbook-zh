# 第四章 指纹识别

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 4.1 Netcat 特征抓取

Netcat 是个多用途的网络工具，可以用于在 Kali 中执行多个信息收集和扫描任务。这个秘籍展示了如何使用 Netcat 获取服务特征，以便识别和开放端口相关的服务。

### 准备

为了使用 Netcat 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

为了使用 Netcat 抓取服务特征，我们必须与建立远程系统的目标端口建立套接字连接。为了快速理解 Netcat 的用法，以及如何用于该目的，我们可以输出使用方法。这可以使用`-h`选项来完成：

```
root@KaliLinux:~# nc -h 
[v1.10-40] 
connect to somewhere:  nc [-options] hostname port[s] [ports] ... 
listen for inbound:    nc -l -p port [-options] [hostname] [port] 
options:
    -c shell commands as `-e'; use /bin/sh to exec [dangerous!!]   
    -e filename      program to exec after connect [dangerous!!]    
    -b          allow broadcasts   
    -g gateway      source-routing hop point[s], up to 8  
    -G num          source-routing pointer: 4, 8, 12, ...    
    -h          this cruft
    -i secs          delay interval for lines sent, ports scanned        
    -k                      set keepalive option on socket    
    -l          listen mode, for inbound connects   
    -n          numeric-only IP addresses, no DNS   
    -o file            hex dump of traffic  
    -p port          local port number   
    -r          randomize local and remote ports   
    -q secs          quit after EOF on stdin and delay of secs  
    -s addr            local source address  
    -T tos          set Type Of Service  
    -t          answer TELNET negotiation 
    -u          UDP mode 
    -v          verbose [use twice to be more verbose]   
    -w secs          timeout for connects and final net reads    
    -z          zero-I/O mode [used for scanning] 
```

通过查看工具提供的多个选项，我们可以判断出，通过指定选项，IP 地址和端口号，我们就可以创建到所需端口的连接。

```
root@KaliLinux:~# nc -vn 172.16.36.135 22 
(UNKNOWN) [172.16.36.135] 22 (ssh) open 
SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 
^C 
```

在所提供的例子中，创建了到 Metasploitable2 系统`172.16.36.135` 端口 22 的链接。`-v`选项用于提供详细输出，`-n`选项用于不使用 DNS 解析来连接到这个 IP 地址。这里我们可以看到，远程主机返回的特征将服务识别为 SSH，厂商为 OpenSSH，甚至还有精确的版本 4.7。Netcat 维护开放连接，所以读取特征之后，你可以按下`Ctrl + C`来强行关闭连接。

```
root@KaliLinux:~# nc -vn 172.16.36.135 21 
(UNKNOWN) [172.16.36.135] 21 (ftp) open 
220 (vsFTPd 2.3.4) 
^C 
```

通过执行相同主机 21 端口上的相似扫描，我们可以轻易获得所运行 FTP 服务的服务和版本信息。每个情况都暴露了大量实用的信息。了解运行在系统上的服务和版本通常是漏洞的关键指示，这可以用于利用或者入侵系统。

### 工作原理

Netcat 能够住区这些服务的特征，因为当客户端设备连接它们的时候，服务的配置会自己开房这些信息。自我开房服务的和版本的最佳实践在过去常常使用，来确保客户端俩连接到了它们想连接的目标。由于开发者的安全意识变强，这个实践变得越来越不普遍。无论如何，它仍旧对于不良开发者，或者历史遗留服务十分普遍，它们会以服务特征的形式提供大量信息。

## 4.2 Python 套接字特征抓取

Python 的套接字模块可以用于连接运行在远程端口上的网络服务。这个秘籍展示饿了如何使用 Python 套接字来获取服务特征，以便识别目标系统上和开放端口相关的服务。

### 准备

为了使用 Python 套接字收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器*VIM 和 Nano”。

### 操作步骤

使用 Python 交互式解释器，我们可以直接与远程网络设备交互。你可以通过 直接调用 Python 解释器来直接和它交互。这里，你可以导入任何打算使用的特定模块。这里我们导入套接字模块。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> import socket 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 21))
>>> bangrab.recv(4096) '220 (vsFTPd 2.3.4)\r\n'
>>> bangrab.close() 
>>> exit() 
```

在提供的例子中，我们使用名`bangrab`创建了新的套接字。`AF_INET`参数用于表示，套接字使用 IPv4 地址，`SOCK_STREAM`参数用于表示使用 TCP 来传输。一旦套接字创建完毕，可以使用`connect`来初始化连接。例子中。`bangrab`套接字连接 Metasploitable2 远程主机`172.16.36.135`的 21 端口。连接后，`recv`函数可以用于从套接字所连接的服务接收内容。假设有可用信息，它会打印它作为输出。这里，我们可以看到由运行在 Metasploitable2 服务器上的 FTP 服务提供的特征。最后，`close`函数可以用于完全结束与远程服务的连接。如果我们尝试连接不接受连接的服务，Python 解释器会返回错误。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> import socket 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 443)) 
Traceback (most recent call last):  
    File "<stdin>", line 1, in <module>  
    File "/usr/lib/python2.7/socket.py", line 224, in meth    
        return getattr(self._sock,name)(*args) 
socket.error: [Errno 111] Connection refused 
>>> exit() 
```

如果我们尝试连接 Metasploitable2 系统上的 TCP 443 端口，会返回一个错误，表示连接被拒绝。这是因为这个远程端口上没有运行服务。但是，即使当存在服务运行在目标端口时，也不等于就能得到服务的特征。这可以通过与 Metasploitable2 系统的 TCP 80 端口建立连接来看到。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information.

>>> import socket 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 80)) 
>>> bangrab.recv(4096) 
```

运行在该系统 80 端口上的服务接受连接，但是不提供服务特征给连接客户端。如果`recv`函数被调用，但是不提供任何数据给接受者，这个函数会被阻塞。为了使用 Python 自动化收集特征，我们必须使用替代方案来识别是否可以抓取到特征，在调用这个函数之前。`select`函数为这个问题提供了便利的解决方案。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> import socket 
>>> import select 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 80)) 
>>> ready = select.select([bangrab],[],[],1) 
>>> if ready[0]: 
...     print bangrab.recv(4096) 
... else: 
...     print "No Banner" 
... No Banner 
```

`select`对象被创建，并赋给了变量`ready`。这个对象被传入了 4 个参数，包括读取列表，写入列表，异常列表，和定义超时秒数的整数值。这里，我们仅仅需要识别套接字什么时候可以读取，所以第二个和第三个参数都是空的。返回值是一个数组，对应三个列表的每一个。我们仅仅对`bangrab`是否有用任何可读内容感兴趣。为了判断是否是这样，我们可以测试数组的第一个值，并且如果值讯在，我们可以从套接字中接受内容。整个过程可以使用 Python 可执行脚本来自动化：

```
#!/usr/bin/python

import socket 
import select 
import sys

if len(sys.argv) != 4:
    print "Usage - ./banner_grab.py [Target-IP] [First Port] [Last     Port]"   
    print "Example - ./banner_grab.py 10.0.0.5 1 100"   
    print "Example will grab banners for TCP ports 1 through 100 on     10.0.0.5"   
    sys.exit()

ip = sys.argv[1] 
start = int(sys.argv[2]) 
end = int(sys.argv[3])
for port in range(start,end):   
try:      
    bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      
    bangrab.connect((ip, port))      
    ready = select.select([bangrab],[],[],1)      
    if ready[0]:         
        print "TCP Port " + str(port) + " - " + bangrab.recv(4096)         
        bangrab.close()   
except: 
    pass
```

在提供的脚本中，三个参数作为输入接受。第一个参数包含用于测试服务特征的 IP 地址。第二个参数指明了被扫描的端口范围的第一个端口，第三个和最后一个参数指明了最后一个端口。执行过程中，这个脚本会使用 Python 套接字来连接所有远程系统的范围内的端口值。并且会收集和打印所有识别出的服务特征。这个脚本可以通过修改文件权限之后直接从所在目录中调用来执行：

```
root@KaliLinux:~# chmod 777 banner_grab.py 
root@KaliLinux:~# ./banner_grab.py 172.16.36.135 1 65535 

TCP Port 21 - 220 (vsFTPd 2.3.4)

TCP Port 22 - SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1

TCP Port 23 - ???? ??#??' 
TCP Port 25 - 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

TCP Port 512 - Where are you?

TCP Port 514 - 
TCP Port 1524 - root@metasploitable:/# 

TCP Port 2121 - 220 ProFTPD 1.3.1 Server (Debian)  
[::ffff:172.16.36.135]

TCP Port 3306 - > 
5.0.51a-3ubuntu5?bo,(${c\,#934JYb^4'fM 
TCP Port 5900 - RFB 003.003

TCP Port 6667 - :irc.Metasploitable.LAN NOTICE AUTH :*** Looking up  your hostname... 
:irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your  hostname; using your IP address instead

TCP Port 6697 - :irc.Metasploitable.LAN NOTICE AUTH :*** Looking up  your hostname...

```

### 工作原理

这个秘籍中引入的 Python 脚本的原理是使用套接字库。脚本遍历每个指定的目标端口地址，并尝试与特定端口初始化 TCP 连接。如果建立了连接并接受到来自目标服务的特征，特征之后会打印在脚本的输出中。如果连接不能与远程端口建立，脚本之后会移动到循环汇总的下一个端口地址。与之相似，如果建立了连接，但是没有返回任何特征，连接会被关闭，并且脚本会继续扫描循环内的下一个值。

## 4.3 Dmitry 特征抓取

Dmitry 是个简单但高效的工具，可以用于连接运行在远程端口上的网络服务。这个秘籍真实了如何使用Dmitry 扫描来获取服务特征，以便识别和开放端口相关的服务。

### 准备

为了使用 Dmitry 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 工作原理

就像在这本书的端口扫描秘籍中讨论的那样 Dmitry可以用于对 150 个常用服务的端口执行快速的 TCP 端口扫描。这可以使用`-p`选项来执行：

```
root@KaliLinux:~# dmitry -p 172.16.36.135 
Deepmagic Information Gathering Tool 
"There be some deep magic going on"

ERROR: Unable to locate Host Name for 172.16.36.135 
Continuing with limited modules 
HostIP:172.16.36.135 HostName:

Gathered TCP Port information for 172.16.36.135 
--------------------------------

 Port     State
 
21/tcp     open 
22/tcp     open 
23/tcp     open 
25/tcp     open 
53/tcp     open 
80/tcp     open 
111/tcp        open 
139/tcp        open

Portscan Finished: Scanned 150 ports, 141 ports were in state closed 
```

这个端口扫描选项是必须的，以便使用 Dmitry 执行特征抓取。也可以在尝试连接这 150 个端口时，让 Dmitry 抓取任何可用的特征。这可以使用`-b`选项和`-p`选项来完成。

```
root@KaliLinux:~# dmitry -pb 172.16.36.135 
Deepmagic Information Gathering Tool
"There be some deep magic going on"

ERROR: Unable to locate 
Host Name for 172.16.36.135 Continuing with limited modules 
HostIP:172.16.36.135 HostName:

Gathered TCP Port information for 172.16.36.135 
--------------------------------

 Port     State
 
21/tcp     open 
>> 220 (vsFTPd 2.3.4)

22/tcp     open 
>> SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1

23/tcp     open 
>> ???? ??#??' 
25/tcp     open 
>> 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

53/tcp     open 
80/tcp     open 
111/tcp        open 
139/tcp        open

Portscan Finished: Scanned 150 ports, 141 ports were in state closed
```

### 工作原理

Dmitry 是个非常简单的命令工具，可以以少量开销执行特征抓取任务。比起指定需要尝试特征抓取的端口，Dmitry 可以自动化这个过程，通过仅仅在小型的预定义和常用端口集合中尝试特征抓取。来自运行在这些端口地址的特征之后会在脚本的终端输出中显示。

## 4.4 Nmap NSE 特征抓取

Nmap 拥有集成的 Nmap 脚本引擎（NSE），可以用于从运行在远程端口的网络服务中读取特征。这个秘籍展示了如何使用 Nmap NSE 来获取服务特征，以便识别与目标系统的开放端口相关的服务。

### 准备

为了使用 Nmap NSE 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

Nmap NSE 脚本可以在 Nmap 中使用`--script`选项，之后指定脚本名称来调用。对于这个特定的脚本，会使用`-sT`全连接扫描，因为服务特征只能通过建立 TCP 全连接在收集。这个脚本会在通过 Nmap 请求扫描的相同端口上使用。

```
root@KaliLinux:~# nmap -sT 172.16.36.135 -p 22 --script=banner

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 04:56 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00036s latency). 
PORT   STATE SERVICE 
22/tcp open  ssh 
|_banner: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds 
```

在提供的例子中，扫描了 Metasploitable2 系统的端口 22。除了表明端口打开之外，Nmap 也使用特征脚本来收集与该端口相关的服务特征。可以使用`--notation`，在端口范围内使用相同机制。

```
root@KaliLinux:~# nmap -sT 172.16.36.135 -p 1-100 --script=banner

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 04:56 EST
Nmap scan report for 172.16.36.135 
Host is up (0.0024s latency). 
Not shown: 94 closed ports 
PORT   STATE SERVICE 
21/tcp open  ftp 
|_banner: 220 (vsFTPd 2.3.4) 
22/tcp open  ssh 
|_banner: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 
23/tcp open  telnet 
|_banner: \xFF\xFD\x18\xFF\xFD \xFF\xFD#\xFF\xFD' 
25/tcp open  smtp 
|_banner: 220 metasploitable.localdomain ESMTP Postfix (Ubuntu) 
53/tcp open  domain 
80/tcp open  http 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 10.26 seconds
```

### 工作原理

另一个用于执行特征抓取的选择就是使用 Nmap NSE 脚本。这可以以两种方式有效简化信息收集过程：首先，由于 Nmap 已经存在于你的工具库中，经常用于目标和服务探索；其次，因为特征抓取过程可以和这些扫描一起执行。 带有附加脚本选项和特征参数的 TCP 连接扫描可以完成服务枚举和特征收集的任务。

## 4.5 Amap 特征抓取

Amap 是个应用映射工具，可以用于从运行在远程端口上的网络设备中读取特征。这个秘籍展示了如何使用 Amap 来获取服务特征，以便识别和目标系统上的开放端口相关的服务。

### 准备

为了使用 Amap 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

Amap 中的`-B`选项可以用于以特征模式运行应用。这会使其收集特定 IP 地址和独舞端口的特征。Amap 可以通过指定远程 IP 地址和服务号码来收集单个服务的特征。

```
root@KaliLinux:~# amap -B 172.16.36.135 21 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:04:58 -  BANNER mode

Banner on 172.16.36.135:21/tcp : 220 (vsFTPd 2.3.4)\r\n

amap v5.4 finished at 2013-12-19 05:04:58 
```

这个例子中，Amap 从 Metasploitable2 系统`172.16.36.135`的 21 端口抓取了服务特征。这个命令也可以修改来扫描端口的序列范围。为了在所有可能的 TCP 端口上执行扫描，需要奥妙所有可能的端口地址。定义了来源和目标端口地址的 TCP 头部部分是 16 位长，每一位可以为值 1 或者 0。所以一共有`2 **16`或 65536 个 TCP 端口地址。为了扫描所有可能的地址空间，必须提供 1 到 65535 的 范围。

```
root@KaliLinux:~# amap -B 172.16.36.135 1-65535 
amap v5.4 (www.thc.org/thc-amap) started at 2014-01-24 15:54:28 -  BANNER mode

Banner on 172.16.36.135:22/tcp : SSH-2.0-OpenSSH_4.7p1 Debian- 8ubuntu1\n 
Banner on 172.16.36.135:21/tcp : 220 (vsFTPd 2.3.4)\r\n 
Banner on 172.16.36.135:25/tcp : 220 metasploitable.localdomain  ESMTP Postfix (Ubuntu)\r\n 
Banner on 172.16.36.135:23/tcp :  #' 
Banner on 172.16.36.135:512/tcp : Where are you?\n 
Banner on 172.16.36.135:1524/tcp : root@metasploitable/# 
Banner on 172.16.36.135:2121/tcp : 220 ProFTPD 1.3.1 Server  (Debian) [ffff172.16.36.135]\r\n 
Banner on 172.16.36.135:3306/tcp : >\n5.0.51a- 3ubuntu5dJ$t?xdj,fCYxm=)Q=~$5 
Banner on 172.16.36.135:5900/tcp : RFB 003.003\n 
Banner on 172.16.36.135:6667/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n
Banner on 172.16.36.135:6697/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n

amap v5.4 finished at 2014-01-24 15:54:35
```

Amap 所产生的标准输出提供了一些无用和冗余的信息，可以从输出中去掉。尤其是，移除扫描元数据（`Banner`）以及在整个扫描中都相同的 IP 地址会十分有用。为了移除扫描元数据，我们必须用`grep`搜索输出中的某个短语，它对特定输出项目唯一，并且在扫描元数据中不存在。这里，我们可以`grep`搜索单词`on`。

```
root@KaliLinux:~# amap -B 172.16.36.135 1-65535 | grep "on" 
Banner on 172.16.36.135:22/tcp : SSH-2.0-OpenSSH_4.7p1 Debian- 8ubuntu1\n 
Banner on 172.16.36.135:23/tcp :  #' 
Banner on 172.16.36.135:21/tcp : 220 (vsFTPd 2.3.4)\r\n 
Banner on 172.16.36.135:25/tcp : 220 metasploitable.localdomain  ESMTP Postfix (Ubuntu)\r\n 
Banner on 172.16.36.135:512/tcp : Where are you?\n 
Banner on 172.16.36.135:1524/tcp : root@metasploitable/# 
Banner on 172.16.36.135:2121/tcp : 220 ProFTPD 1.3.1 Server  (Debian) [ffff172.16.36.135]\r\n 
Banner on 172.16.36.135:3306/tcp : >\n5.0.51a- 3ubuntu5\tr>}{pDAY,|$948[D~q<u[ 
Banner on 172.16.36.135:5900/tcp : RFB 003.003\n 
Banner on 172.16.36.135:6697/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n 
Banner on 172.16.36.135:6667/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n 
```

我们可以通过使用冒号分隔符来分割每行输出，并只保留字段 2 到 5，将`Banner on`短语，以及重复 IP 地址从输出中移除。

```
root@KaliLinux:~# amap -B 172.16.36.135 1-65535 | grep "on" | cut  -d ":" -f 2-5 
21/tcp : 220 (vsFTPd 2.3.4)\r\n
22/tcp : SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\n 
1524/tcp : root@metasploitable/# 
25/tcp : 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n
23/tcp :  #' 
512/tcp : Where are you?\n
2121/tcp : 220 ProFTPD 1.3.1 Server (Debian)  [ffff172.16.36.135]\r\n
3306/tcp : >\n5.0.51a-3ubuntu5\nqjAClv0(,v>q?&?J7qW>n 
5900/tcp : RFB 003.003\n 
6667/tcp : irc.Metasploitable.LAN NOTICE AUTH *** Looking up your  hostname...\r\n
6697/tcp : irc.Metasploitable.LAN NOTICE AUTH *** Looking up your  hostname...\r\n

```

### 工作原理

Amap 用于完成特征抓取任务的底层原理和其它所讨论的工具一样。Amap 循环遍历目标端口地址的列表，尝试和每个端口建立连接，之后接收任何返回的通过与服务之间的连接发送的特征。

## 4.6 Nmap 服务识别

虽然特征抓取是非常有利的信息来源，服务特征中的版本发现越来越不重要。Nmap 拥有服务识别功能，不仅仅是简单的特征抓取机制。这个秘籍展示了如何使用 Nmap 基于探测响应的分析执行服务识别。

### 准备

为了使用 Nmap 执行服务识别，你需要拥有运行可被探测的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

为了理解 Nmap 服务是被功能的高效性，我们应该考虑不提供自我开放的服务特征的服务。通过使用 Netcat 连接 Metasploitable2 系统的 TCP 80 端口（这个技巧在这一章的“Netcat 特征抓取”秘籍中讨论过了），我们可以看到，仅仅通过建立 TCP 连接，不能得到任何服务特征。

```
root@KaliLinux:~# nc -nv 172.16.36.135 80 
(UNKNOWN) [172.16.36.135] 80 (http) open 
^C
```

之后，为了在相同端口上执行 Nmap 扫描，我们可以使用`-sV`选项，并且指定 IP 和端口。

```
root@KaliLinux:~# nmap 172.16.36.135 -p 80 -sV

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 05:20 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00035s latency). 
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2) 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Service detection performed. Please report any incorrect results  at http://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 6.18 seconds
```

你可以看到在这个示例中，Nmap 能够识别该服务，厂商，以及产品的特定版本。这个服务识别功能也可以用于对特定端口列表使用。这在 Nmap 中并不需要指定端口，Nmap 会扫描 1000 个常用端口，并且尝试识别所有识别出来的监听服务。

```
root@KaliLinux:~# nmap 172.16.36.135 -sV

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 05:20 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00032s latency). 
Not shown: 977 closed ports 
PORT     STATE SERVICE     VERSION 
21/tcp   open  ftp         vsftpd 2.3.4 
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol  2.0) 
23/tcp   open  telnet      Linux telnetd 
25/tcp   open  smtp        Postfix smtpd 
53/tcp   open  domain      ISC BIND 9.4.2 
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2) 
111/tcp  open  rpcbind     2 (RPC #100000) 
139/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP) 
445/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP) 
512/tcp  open  exec        netkit-rsh rexecd 
513/tcp  open  login? 
514/tcp  open  tcpwrapped
1099/tcp open  rmiregistry GNU Classpath grmiregistry 
1524/tcp open  ingreslock? 
2049/tcp open  nfs         2-4 (RPC #100003) 
2121/tcp open  ftp         ProFTPD 1.3.1 
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5 
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7 
5900/tcp open  vnc         VNC (protocol 3.3) 
6000/tcp open  X11         (access denied) 
6667/tcp open  irc         Unreal ircd 
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3) 
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1 MAC Address: 00:0C:29:3D:84:32 (VMware) 
Service Info: Hosts:  metasploitable.localdomain, localhost,  irc.Metasploitable.LAN; OSs: Unix, Linux; CPE:  cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results  at http://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 161.49 seconds
```

### 工作原理

Nmap 服务识别会发送一系列复杂的探测请求，之后分析这些请求的响应，尝试基于服务特定的签名和预期行为，来识别服务。此外，你可以看到 Nmap 服务识别输出的底部，Nmap 依赖于用户的反馈，以便确保服务签名保持可靠。

## 4.7 Amap 服务识别

Amap 是 Nmap 的近亲，尤其为识别网络服务而设计。这个秘籍中，我们会探索如何使用 Amap 来执行服务识别。

### 准备

为了使用 Amap 执行服务识别，你需要拥有运行可被探测的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

为了在单一端口上执行服务识别，以特定的 IP 地址和端口号来运行 Amap。

```
root@KaliLinux:~# amap 172.16.36.135 80 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:26:13 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:80/tcp matches http
Protocol on 172.16.36.135:80/tcp matches http-apache-2

Unidentified ports: none.

amap v5.4 finished at 2013-12-19 05:26:19
```

Amap 也可以使用破折号记法扫描端口号码序列。为了这样你工作，以特定 IP 地址和端口范围来执行`amap`，端口范围由范围的第一个端口号，破折号，和范围的最后一个端口号指定。

```
root@KaliLinux:~# amap 172.16.36.135 20-30 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:28:16 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:25/tcp matches smtp 
Protocol on 172.16.36.135:21/tcp matches ftp 
Protocol on 172.16.36.135:25/tcp matches nntp 
Protocol on 172.16.36.135:22/tcp matches ssh 
Protocol on 172.16.36.135:22/tcp matches ssh-openssh 
Protocol on 172.16.36.135:23/tcp matches telnet

Unidentified ports: 172.16.36.135:20/tcp 172.16.36.135:24/tcp  172.16.36.135:26/tcp 172.16.36.135:27/tcp 172.16.36.135:28/tcp  172.16.36.135:29/tcp 172.16.36.135:30/tcp (total 7).

amap v5.4 finished at 2013-12-19 05:28:17

```

除了识别任何服务，它也能够在输出末尾生产列表，表明任何未识别的端口。这个列表不仅仅包含运行不能识别的服务的开放端口，也包含所有扫描过的关闭端口。但是这个输出仅在扫描了 10 个端口时易于管理，当扫描更多端口范围之后会变得十分麻烦。为了去掉未识别端口的信息，可以使用`-q`选项：

```
root@KaliLinux:~# amap 172.16.36.135 1-100 -q 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:29:27 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:21/tcp matches ftp 
Protocol on 172.16.36.135:25/tcp matches smtp 
Protocol on 172.16.36.135:22/tcp matches ssh 
Protocol on 172.16.36.135:22/tcp matches ssh-openssh 
Protocol on 172.16.36.135:23/tcp matches telnet 
Protocol on 172.16.36.135:80/tcp matches http 
Protocol on 172.16.36.135:80/tcp matches http-apache-2 
Protocol on 172.16.36.135:25/tcp matches nntp 
Protocol on 172.16.36.135:53/tcp matches dns

amap v5.4 finished at 2013-12-19 05:29:39 
```

要注意，Amap 会指明常规匹配和更加特定的签名。在这个例子中，运行在端口 22 的服务被识别为匹配 SSH 签名，也匹配更加具体的 OpenSSH 签名。将服务签名和服务特征展示在一起很有意义。特征可以使用`-b`选项，附加到和每个端口相关的信息后面：

```
root@KaliLinux:~# amap 172.16.36.135 1-100 -qb 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:32:11 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:21/tcp matches ftp - banner: 220 (vsFTPd  2.3.4)\r\n530 Please login with USER and PASS.\r\n 
Protocol on 172.16.36.135:22/tcp matches ssh - banner: SSH-2.0- OpenSSH_4.7p1 Debian-8ubuntu1\n 
Protocol on 172.16.36.135:22/tcp matches ssh-openssh - banner:  SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\n 
Protocol on 172.16.36.135:25/tcp matches smtp - banner: 220  metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n221 2.7.0  Error I can break rules, too. Goodbye.\r\n 
Protocol on 172.16.36.135:23/tcp matches telnet - banner:  #'
Protocol on 172.16.36.135:80/tcp matches http - banner: HTTP/1.1  200 OK\r\nDate Sat, 26 Oct 2013 014818 GMT\r\nServer Apache/2.2.8  (Ubuntu) DAV/2\r\nX-Powered-By PHP/5.2.4-2ubuntu5.10\r\nContent- Length 891\r\nConnection close\r\nContent-Type  text/html\r\n\r\n<html><head><title>Metasploitable2 -  Linux</title>< 
Protocol on 172.16.36.135:80/tcp matches http-apache-2 - banner:  HTTP/1.1 200 OK\r\nDate Sat, 26 Oct 2013 014818 GMT\r\nServer  Apache/2.2.8 (Ubuntu) DAV/2\r\nX-Powered-By PHP/5.2.4- 2ubuntu5.10\r\nContent-Length 891\r\nConnection close\r\nContent- Type text/html\r\n\r\n<html><head><title>Metasploitable2 -  Linux</title>< 
Protocol on 172.16.36.135:53/tcp matches dns - banner: \f

amap v5.4 finished at 2013-12-19 05:32:23 
```

服务识别会扫描大量端口或者在多有 65536 个端口上执行复杂的扫描，如果每个服务上都探测了每个可能的签名，这样会花费大量时间。为了增加服务识别扫描的速度，我们可以使用`-1`参数，在匹配到特定特性签名之后取消特定服务的分析。

```
root@KaliLinux:~# amap 172.16.36.135 1-100 -q1 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:33:16 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:21/tcp matches ftp 
Protocol on 172.16.36.135:22/tcp matches ssh 
Protocol on 172.16.36.135:25/tcp matches smtp 
Protocol on 172.16.36.135:23/tcp matches telnet 
Protocol on 172.16.36.135:80/tcp matches http 
Protocol on 172.16.36.135:80/tcp matches http-apache-2 
Protocol on 172.16.36.135:53/tcp matches dns

amap v5.4 finished at 2013-12-19 05:33:16
```

Amap 服务识别的底层原理和 Nmap 相似。它注入了一系列探测请求，来尝试请求唯一的响应，它可以用于识别运行在特定端口的软件的版本和服务。但是，要注意的是，虽然 Amap 是个服务识别的替代选项，它并不像 Nmap 那样保持更新和拥有良好维护。所以，Amap 不太可能产生可靠的结果。

## 4.8 Scapy 操作系统识别

由很多技术可以用于尝试识别操作系统或其它设备的指纹。高效的操作系统识别功能非常健壮并且会使用大量的技术作为分析因素。Scapy 可以用于独立分析任何此类因素。这个秘籍展示了如何通过检测返回的 TTL 值，使用 Scapy 执行 OS 识别。

### 准备

为了使用 Scapy 来识别 TTL 响应中的差异，你需要拥有运行 Linux/Unix 操作系统和运行 Windows 操作系统的远程系统。提供的例子使用 Metasploitable2 和 Windows XP。在本地实验环境中配置系统的更多信息请参考第一章的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器*VIM 和 Nano”。

### 操作步骤

Windows 和 Linux/Unix 操作系统拥有不同的 TTL 默认起始值。这个因素可以用于尝试识别操作系统的指纹。这些值如下：

| 操作系统 | TTL 起始值 |
| --- | --- |
| Windows | 128 |
| Linux/Unix | 64 |

一些基于 Unix 的系统会的 TTL 默认起始值为 225 。但是，出于简单性考虑，我们会使用所提供的值作为这个秘籍的前提。为了分析来自远程系统的响应中的 TTL，我们首先需要构建请求。这里，我们使用 ICMP 回响请求。为了发送 ICMP请求，我们必须首先构建请求的层级。我们需要首先构建的是 IP 层。

```
root@KaliLinux:~# scapy Welcome to Scapy (2.2.0) >>> linux = "172.16.36.135"

>>> windows = "172.16.36.134" 
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
>>> i.dst = linux 
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

为了构建请求的 IP 层，我们应该将`IP`对象赋给`i`变量。通过调用`display`函数，我们可以确认对象的属性配置。通常，发送和接受地址都设为回送地址`127.0.0.1`，所以我们需要将其改为目标地址的值，将`i.dst`改为我们希望扫描的地址的字符串值。

通过再次调用`display`函数，我们可以看到不仅仅目标地址被更新，Scapy 也会将源 IP 地址自动更新为何默认接口相关的地址。现在我们成功构造了请求的 IP 层。既然我们构建了请求的 IP 层，我们应该开始构建 ICMP 层了。

```
>>> ping = ICMP() 
>>> ping.display() 
###[ ICMP ]###  
    type= echo-request  
    code= 0  
    chksum= None  
    id= 0x0  
    seq= 0x0
```

为了构建请求的 ICMP 层，我们会使用和 IP 层相同的技巧。在提供的例子中，`ICMP`对象赋给了`ping`遍历。像之前那样，默认的配置可以用过调用`dispaly`函数来确认。通常 ICMP 类型已经设为了`echo-request`。既然我们创建了 IP 和 ICMP 层，我们需要通过叠放这些层来构建请求。

```
>>> request = (i/ping) 
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
    proto= icmp  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\ 
###[ ICMP ]###     
    type= echo-request     
    code= 0     
    chksum= None     
    id= 0x0     
    seq= 0x0
```

IP 和 ICMP 层可以通过以斜杠分隔遍历来叠放。这些层可以赋给新的变量，它代表我们整个请求。`display`函数之后可以调用来查看请求配置。一旦请求构建完毕，我么可以将其传递给`sr1`函数，以便分析响应。

```
>>> ans = sr1(request) 
Begin emission: 
....................Finished to send 1 packets. 
....* 
Received 25 packets, got 1 answers, remaining 0 packets 
>>> ans.display() 
###[ IP ]###  
    version= 4L  
    ihl= 5L  
    tos= 0x0  
    len= 28  
    id= 64067  
    flags=   
    frag= 0L  
    ttl= 64  
    proto= icmp  
    chksum= 0xdf41  
    src= 172.16.36.135  
    dst= 172.16.36.180  
    \options\ 
###[ ICMP ]###     
    type= echo-reply     
    code= 0     
    chksum= 0xffff     
    id= 0x0     
    seq= 0x0 
###[ Padding ]###        
    load=  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\ x00\x00'
```

相同的请求可以不通过独立构建和叠放每一层来构建。反之，我们可以使用单行的命令，通过直接调用函数并传递合适参数：

```
>>> ans = sr1(IP(dst=linux)/ICMP()) 
.Begin emission: 
...*Finished to send 1 packets.

Received 5 packets, got 1 answers, remaining 0 packets 
>>> ans 
<IP  version=4L ihl=5L tos=0x0 len=28 id=64068 flags= frag=0L  ttl=64 proto=icmp chksum=0xdf40 src=172.16.36.135  dst=172.16.36.180 options=[] |<ICMP  type=echo-reply code=0  chksum=0xffff id=0x0 seq=0x0 |<Padding   load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00' |>>> 
```

要注意来自 Linux 系统的响应的 TTL 值为 64。同一测试可以对 Windows 系统的 IP 地址执行，我们应该注意到响应中 TTL 值的差异。

```
>>> ans = sr1(IP(dst=windows)/ICMP()) 
.Begin emission: 
......Finished to send 1 packets. 
....* 
Received 12 packets, got 1 answers, remaining 0 packets 
>>> ans 
<IP  version=4L ihl=5L tos=0x0 len=28 id=24714 flags= frag=0L  ttl=128 proto=icmp chksum=0x38fc src=172.16.36.134  dst=172.16.36.180 options=[] |<ICMP  type=echo-reply code=0  chksum=0xffff id=0x0 seq=0x0 |<Padding   load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00' |>>>
```

要注意由 Windows 系统返回的响应的 TTL 为 128。这个响应可以轻易在 Python 中测试：


```
root@KaliLinux:~# python Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import *
WARNING: No route found for IPv6 destination :: (no default  route?) 
>>> ans = sr1(IP(dst="172.16.36.135")/ICMP()) 
.Begin emission: 
............Finished to send 1 packets. 
....* 
Received 18 packets, got 1 answers, remaining 0 packets 
>>> if int(ans[IP].ttl) <= 64: 
...     print "Host is Linux" 
... else: 
...     print "Host is Windows" 
... Host is Linux 
>>> ans = sr1(IP(dst="172.16.36.134")/ICMP()) 
.Begin emission: 
.......Finished to send 1 packets. 
....* 
Received 13 packets, got 1 answers, remaining 0 packets 
>>> if int(ans[IP].ttl) <= 64: 
...     print "Host is Linux" 
... else: 
...     print "Host is Windows" 
... Host is Windows 
```

通过发送相同请求，可以测试 TTL 值的相等性来判断是否小于等于 64。这里，我们可以假设设备运行 Linux/Unix 操作系统。否则，如果值大于 64，我们可以假设设备可能运行 Windows 操作系统。整个过程可以使用 Python 可执行脚本来自动化：

```py
#!/usr/bin/python

from scapy.all 
import * import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
import sys

if len(sys.argv) != 2:   
    print "Usage - ./ttl_id.py [IP Address]"   
    print "Example - ./ttl_id.py 10.0.0.5"
    print "Example will perform ttl analysis to attempt to determine     whether the system is Windows or Linux/Unix"   
    sys.exit()

ip = sys.argv[1]

ans = sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0) 
if ans == None:   
    print "No response was returned" 
elif int(ans[IP].ttl) <= 64:   
    print "Host is Linux/Unix" 
else:   
    print "Host is Windows" 
```

这个 Python 脚本接受单个参数，由被扫描的 IP 地址组成。基于返回的响应中的 TTL，脚本会猜测远程系统。这个脚本可以通过使用`chmod`修改文件许可，并且直接从所在目标调用来执行：

```
root@KaliLinux:~# chmod 777 ttl_id.py 
root@KaliLinux:~# ./ttl_id.py 
Usage - ./ttl_id.py [IP Address] 
Example - ./ttl_id.py 10.0.0.5 
Example will perform ttl analysis to attempt to determine whether the  system is Windows or Linux/Unix 
root@KaliLinux:~# ./ttl_id.py 172.16.36.134 Host is Windows 
root@KaliLinux:~# ./ttl_id.py 172.16.36.135 Host is Linux/Unix
```

### 工作原理

Windows 操作系统的网络流量的 TTL 起始值通常为 128，然而 Linux/Unix 操作系统为 64。通过假设不高于 64 应该为其中一种系统，我们可以安全地假设 Windows 系统的回复中 TTL 为 65 到 128，而 Linux/Unix 系统的回复中 TTL 为 1 到 64。当扫描系统和远程目标之间存在设备，并且设备拦截请求并重新封包的时候，这个识别方式就会失效。
