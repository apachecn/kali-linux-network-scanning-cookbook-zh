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

```
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
