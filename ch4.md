# 第四章 指纹识别

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 4.1 Netcat 特征抓取

Netcat 是个多用途的网络工具，可以用于在 Kali 中执行多个信息收集和扫描任务。这个秘籍展示了如何使用 Netcat 获取服务特征，以便识别和开放端口相关的服务。

### 准备

为了使用 Netcat 收集服务特征，在客户端服务连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

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

Netcat 能够住区这些服务的特征，因为当客户端服务连接它们的时候，服务的配置会自己开房这些信息。自我开房服务的和版本的最佳实践在过去常常使用，来确保客户端俩连接到了它们想连接的目标。由于开发者的安全意识变强，这个实践变得越来越不普遍。无论如何，它仍旧对于不良开发者，或者历史遗留服务十分普遍，它们会以服务特征的形式提供大量信息。

## 4.2 Python 套接字特征抓取

Python 的套接字模块可以用于连接运行在远程端口上的网络服务。这个秘籍展示饿了如何使用 Python 套接字来获取服务特征，以便识别目标系统上和开放端口相关的服务。

### 准备

为了使用 Python 套接字收集服务特征，在客户端服务连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器*VIM 和 Nano”。

### 操作步骤

使用 Python 交互式解释器，我们可以直接与远程网络设备交互。你可以通过 直接调用 Python 解释器来直接和它交互。这里，你可以导入任何打算使用的特定模块。这里我们导入套接字模块。

``
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

为了使用 Dmitry 套接字收集服务特征，在客户端服务连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

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
