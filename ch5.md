# 第五章 漏洞扫描

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

尽管可以通过查看服务指纹的结果，以及研究所识别的版本的相关漏洞来识别许多潜在漏洞，但这通常需要非常大量时间。 存在更多的精简备选方案，它们通常可以为你完成大部分这项工作。 这些备选方案包括使用自动化脚本和程序，可以通过扫描远程系统来识别漏洞。 未验证的漏洞扫描程序的原理是，向服务发送一系列不同的探针，来尝试过去表明存在漏洞的响应。 或者，经验证的漏洞扫描器会使用提供所安装的应用，运行的服务，文件系统和注册表内容信息的凭证，来直接查询远程系统。

## 5.1 Nmap 脚本引擎漏洞扫描

Nmap脚本引擎（NSE）提供了大量的脚本，可用于执行一系列自动化任务来评估远程系统。 Kali中可以找到的现有NSE脚本分为多个不同的类别，其中之一是漏洞识别。


### 准备

要使用NSE执行漏洞分析，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，会使用存在 SMB 服务漏洞的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章“安装Windows Server”秘籍。

### 操作步骤

许多不同的方法可以用于识别与任何给定的NSE脚本相关联的功能。 最有效的方法之一是使用位于Nmap脚本目录中的`script.db`文件。 要查看文件的内容，我们可以使用`cat`命令，像这样：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/script.db | more 
Entry { filename = "acarsd-info.nse", categories = { "discovery", "safe", } } 
Entry { filename = "address-info.nse", categories = { "default", "safe", } } 
Entry { filename = "afp-brute.nse", categories = { "brute", "intrusive", } } 
Entry { filename = "afp-ls.nse", categories = { "discovery", "safe", } } 
Entry { filename = "afp-path-vuln.nse", categories = { "exploit", "intrusive", " vuln", } } 
Entry { filename = "afp-serverinfo.nse", categories = { "default", "discovery", "safe", } } 
Entry { filename = "afp-showmount.nse", categories = { "discovery", "safe", } } 
Entry { filename = "ajp-auth.nse", categories = { "auth", "default", "safe", } }
Entry { filename = "ajp-brute.nse", categories = { "brute", "intrusive", } } 
Entry { filename = "ajp-headers.nse", categories = { "discovery", "safe", } } 
Entry { filename = "ajp-methods.nse", categories = { "default", "safe", } } 
Entry { filename = "ajp-request.nse", categories = { "discovery", "safe", } }
```

这个`script.db`文件是一个非常简单的索引，显示每个NSE脚本的文件名及其所属的类别。 这些类别是标准化的，可以方便地对特定类型的脚本进行`grep`。 漏洞扫描脚本的类别名称是`vuln`。 要识别所有漏洞脚本，需要对`vuln`术语进行`grep`，然后使用`cut`命令提取每个脚本的文件名。像这样：

```
root@KaliLinux:~# grep vuln /usr/share/nmap/scripts/script.db | cut -d "\"" -f 2 
afp-path-vuln.nse 
broadcast-avahi-dos.nse distcc-cve2004-2687.nse 
firewall-bypass.nse 
ftp-libopie.nse 
ftp-proftpd-backdoor.nse 
ftp-vsftpd-backdoor.nse 
ftp-vuln-cve2010-4221.nse 
http-awstatstotals-exec.nse 
http-axis2-dir-traversal.nse 
http-enum.nse http-frontpage-login.nse 
http-git.nse http-huawei-hg5xx-vuln.nse 
http-iis-webdav-vuln.nse 
http-litespeed-sourcecode-download.nse 
http-majordomo2-dir-traversal.nse 
http-method-tamper.nse http-passwd.nse 
http-phpself-xss.nse http-slowloris-check.nse 
http-sql-injection.nse 
http-tplink-dir-traversal.nse
```

为了进一步评估上述列表中任何给定脚本，可以使用`cat`命令来读取`.nse`文件，它与`script.db`目录相同。因为大多数描述性内容通常在文件的开头，建议你将内容传递给`more`，以便从上到下阅读文件，如下所示：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/smb-check-vulns.nse | more 
local msrpc = require "msrpc" 
local nmap = require "nmap" 
local smb = require "smb" 
local stdnse = require "stdnse" 
local string = require "string" 
local table = require "table"

description = [[ 
Checks for vulnerabilities: 
* MS08-067, a Windows RPC vulnerability 
* Conficker, an infection by the Conficker worm 
* Unnamed regsvc DoS, a denial-of-service vulnerability I accidentally found in Windows 2000 
* SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497) 
* MS06-025, a Windows Ras RPC service vulnerability 
* MS07-029, a Windows Dns Server RPC service vulnerability

WARNING: These checks are dangerous, and are very likely to bring down a server. These should not be run in a production environment unless you (and, more importantly, the business) understand the risks! 
```

在提供的示例中，我们可以看到`smb-check-vulns.nse`脚本检测 SMB 服务相关的一些拒绝服务和远程执行漏洞。 这里，可以找到每个评估的漏洞描述，以及 Microsoft 补丁和CVE 编号的引用，还有可以在线查询的其他信息。 通过进一步阅读，我们可以进一步了解脚本，像这样：

```

--@usage 
-- nmap 
--script smb-check-vulns.nse -p445 <host> 
-- sudo nmap -sU -sS 
--script smb-check-vulns.nse -p U:137,T:139 <host> 
---@output

-- Host script results: 
-- | smb-check-vulns: 
-- |   MS08-067: NOT VULNERABLE 
-- |   Conficker: Likely CLEAN 
-- |   regsvc DoS: regsvc DoS: NOT VULNERABLE 
-- |   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE 
-- |   MS06-025: NO SERVICE (the Ras RPC service is inactive) 
-- |_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive) 
--- @args unsafe If set, this script will run checks that, if the system isn't 
--       patched, are basically guaranteed to crash something. Remember that 
--       non-unsafe checks aren't necessarily safe either) 
-- @args safe   If set, this script will only run checks that are known (or at 
--       least suspected) to be safe. 
----------------------------------------------------------------------
```

通过进一步阅读，我们可以找到脚本特定的参数，适当的用法以及脚本预期输出的示例的详细信息。要注意一个事实，有一个不安全的参数，可以设置为值0（未激活）或1（激活）。这实际上是Nmap漏洞脚本中的一个常见的现象，理解它的用法很重要。默认情况下，不安全参数设置为0。当设置此值时，Nmap不执行任何可能导致拒绝服务的测试。虽然这听起来像是最佳选择，但它通常意味着许多测试的结果将不太准确，并且一些测试根本不会执行。建议激活不安全参数以进行更彻底和准确的扫描，但这只应在授权测试情况下针对生产系统执行。要运行漏洞扫描，应使用`nmap --script`参数定义特定的NSE脚本，并使用`nmap --script-args`参数传递所有脚本特定的参数。此外，要以最小的干扰输出来运行漏洞扫描，应将Nmap配置为仅扫描与被扫描服务对应的端口，如下所示：

```
root@KaliLinux:~# nmap --script smb-check-vulns.nse --scriptargs=unsafe=1 -p445 172.16.36.225

Starting Nmap 6.25 ( http://nmap.org ) at 2014-03-09 03:58 EDT 
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

Nmap done: 1 IP address (1 host up) scanned in 18.21 seconds 
```

还有一个需要注意的NSE脚本，因为它提供了一个重要的漏洞扫描方式。 这个脚本是`smb-vulnms10-061.nse`。 这个脚本的细节可以通过使用`cat`命令`pipe`到`more`，从上到下阅读脚本来获得：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/smb-vuln-ms10-061.nse | more 
local bin = require "bin" 
local msrpc = require "msrpc" 
local smb = require "smb" 
local string = require "string" 
local vulns = require "vulns" 
local stdnse = require "stdnse"
description = [[ 
Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability. 
```

此漏洞是Stuxnet蠕虫利用的四个漏洞之一。 该脚本以安全的方式检查`vuln`，而没有崩溃远程系统的可能性，因为这不是内存损坏漏洞。 为了执行检测，它需要访问远程系统上的至少一个共享打印机。 默认情况下，它尝试使用LANMAN API枚举打印机，在某些系统上通常不可用。 在这种情况下，用户应将打印机共享名称指定为打印机脚本参数。 要查找打印机共享，可以使用`smb-enum-share`。

此外，在某些系统上，访问共享需要有效的凭据，可以使用`smb`库的参数 `smbuser`和`smbpassword`指定。我们对这个漏洞感兴趣的原因是，在实际被利用之前，必须满足多个因素必须。首先，系统必须运行涉及的操作系统之一（XP，Server 03 SP2，Vista，Server 08或Windows 7）。第二，它必须缺少MS10-061补丁，这个补丁解决了代码执行漏洞。最后，系统上的本地打印共享必须可公开访问。有趣的是，我们可以审计SMB 远程后台打印处理程序服务，以确定系统是否打补丁，无论系统上是否共享了现有的打印机。正因为如此，对于什么是漏洞系统存在不同的解释。一些漏洞扫描程序会将未修补的系统识别为漏洞，但漏洞不能被实际利用。或者，其他漏洞扫描程序（如NSE脚本）将评估所有所需条件，以确定系统是否易受攻击。在提供的示例中，扫描的系统未修补，但它也没有共享远程打印机。看看下面的例子：

```
root@KaliLinux:~# nmap -p 445 172.16.36.225 --script=smb-vuln-ms10-061

Starting Nmap 6.25 ( http://nmap.org ) at 2014-03-09 04:19 EDT 
Nmap scan report for 172.16.36.225 
Host is up (0.00036s latency). 
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 
MAC Address: 00:0C:29:18:11:FB (VMware)

Host script results: 
|_smb-vuln-ms10-061: false

Nmap done: 1 IP address (1 host up) scanned in 13.16 seconds 
```

在提供的示例中，Nmap已确定系统不易受攻击，因为它没有共享远程打印机。尽管确实无法利用此漏洞，但有些人仍然声称该漏洞仍然存在，因为系统未修补，并且可以在管理员决定从该设备共享打印机的情况下利用此漏洞。这就是必须评估所有漏洞扫描程序的结果的原因，以便完全了解其结果。一些扫描其仅选择评估有限的条件，而其他扫描其更彻底。这里很难判断最好的答案是什么。大多数渗透测试人员可能更喜欢被告知系统由于环境变量而不易受到攻击，因此他们不会花费无数小时来试图利用不能利用的漏洞。或者，系统管理员可能更喜欢知道系统缺少MS10-061补丁，以便系统可以完全安全，即使在现有条件下不能利用漏洞。

### 工作原理

大多数漏洞扫描程序通过评估多个不同的响应，来尝试确定系统是否容易受特定攻击。 在一些情况下，漏洞扫描可以简化为与远程服务建立TCP连接，并且通过自开放的特征来识别已知的漏洞版本。 在其他情况下，可以向远程服务发送一系列复杂的特定的探测请求，来试图请求对服务唯一的响应，该服务易受特定的攻击。 在NSE漏洞脚本的示例中，如果激活了`unsafe`参数，漏洞扫描实际上将尝试利用此漏洞。

## 5.2 MSF 辅助模块漏洞扫描

与NSE中提供的漏洞扫描脚本类似，Metasploit还提供了一些有用的漏洞扫描程序。 类似于Nmap的脚本，大多数是相当有针对性的，用于扫描特定的服务。

### 准备

要使用 MSF 辅助模块执行漏洞分析，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，会使用存在 SMB 服务漏洞的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章“安装Windows Server”秘籍。

有多种不同的方法可以用于确定 Metasploit 中的漏洞扫描辅助模块。 一种有效的方法是浏览辅助扫描器目录，因为这是最常见的漏洞识别脚本所在的位置。 看看下面的例子：

```
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/scanner/
mysql# cat mysql_authbypass_hashdump.rb | more 
## 
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit 
# web site for more information on licensing and terms of use. 
#   http://metasploit.com/ 
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL  
  include Msf::Auxiliary::Report
  
  include Msf::Auxiliary::Scanner

  def initialize    
      super(      
          'Name'           => 'MySQL Authentication Bypass Password Dump',      
          'Description'    => %Q{          
              This module exploits a password bypass vulnerability in MySQL in order to extract the usernames and encrypted password hashes from a MySQL server. These hashes are stored as loot for later cracking. 
```

这些脚本的布局是相当标准化的，任何给定脚本的描述可以通过使用`cat`命令，然后将输出`pipe`到`more`，从上到下阅读脚本来确定。 在提供的示例中，我们可以看到该脚本测试了MySQL数据库服务中存在的身份验证绕过漏洞。 或者，可以在MSF控制台界面中搜索漏洞识别模块。 要打开它，应该使用`msfconsole`命令。 搜索命令之后可以与服务相关的特定关键字一同使用，或者可以使用`scanner`关键字查询辅助/扫描器目录中的所有脚本，像这样：

```
msf > search scanner

Matching Modules 
================
   Name                                                                 
   Disclosure Date  Rank    Description   ----                                                                     ---------------  ----    ----------   
   auxiliary/admin/smb/check_dir_file                                                        normal  SMB Scanner Check File/Directory Utility   
   auxiliary/bnat/bnat_scan                                                                  normal  BNAT Scanner
   auxiliary/gather/citrix_published_applications                                            normal  Citrix MetaFrame ICA Published Applications Scanner   
   auxiliary/gather/enum_dns                                                                 normal  DNS Record Scanner and Enumerator    
   auxiliary/gather/natpmp_external_address                                                  normal  NAT-PMP External Address Scanner   
   auxiliary/scanner/afp/afp_login                                                           normal  Apple Filing Protocol Login Utility   
   auxiliary/scanner/afp/afp_server_info                                                     normal  Apple Filing Protocol Info Enumerator   
   auxiliary/scanner/backdoor/energizer_duo_detect                                           normal  Energizer DUO Trojan Scanner   
   auxiliary/scanner/db2/db2_auth                                                            normal  DB2 Authentication Brute Force Utility
```

在识别看起来有希望的脚本时，可以使用`use`命令结合相对路径来激活该脚本。 一旦激活，以下`info`命令可用于读取有关脚本的其他详细信息，包括详细信息，描述，选项和引用：

```
msf > use auxiliary/scanner/rdp/ms12_020_check 
msf  auxiliary(ms12_020_check) > info

       Name: MS12-020 Microsoft Remote Desktop Checker     
       Module: auxiliary/scanner/rdp/ms12_020_check    
       Version: 0    
       License: Metasploit Framework License (BSD)       
       Rank: Normal
       
Provided by:  
    Royce Davis @R3dy_ <rdavis@accuvant.com>  
    Brandon McCann @zeknox <bmccann@accuvant.com>

Basic options:  
    Name     Current Setting  Required  Description  
    ----     ---------------  --------  ----------  RHOSTS                    yes       The target address range or CIDR identifier  
    RPORT    3389             yes       Remote port running RDP  
    THREADS  1                yes       The number of concurrent threads

Description:  
    This module checks a range of hosts for the MS12-020 vulnerability.   
    This does not cause a DoS on the target.
```

一旦选择了模块，`show options`命令可用于识别和/或修改扫描配置。 此命令将显示四个列标题，包括`Name`, `Current Setting`, `Required`, 和`Description`。 `Name`列标识每个可配置变量的名称。 `Current Setting`列列出任何给定变量的现有配置。 `Required`列标识任何给定变量是否需要值。 `Description`列描述每个变量的函数。 可以通过使用`set`命令并提供新值作为参数，来更改任何给定变量的值，如下所示：

```
msf  auxiliary(ms12_020_check) > set RHOSTS 172.16.36.225 
RHOSTS => 172.16.36.225 
msf  auxiliary(ms12_020_check) > run

[*] Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed In this particular case, the system was not found to be vulnerable. However, in the case that a vulnerable system is identified, there is a corresponding exploitation module that can be used to actually cause a denial-of-service on the vulnerable system. This can be seen in the example provided:

msf  auxiliary(ms12_020_check) > use auxiliary/dos/windows/rdp/ms12_020_ maxchannelids 
msf  auxiliary(ms12_020_maxchannelids) > info
       
       Name: MS12-020 Microsoft Remote Desktop Use-After-Free DoS     Module: auxiliary/dos/windows/rdp/ms12_020_maxchannelids    
       Version: 0    
       License: Metasploit Framework License (BSD)       
       Rank: Normal
       
Provided by:  
    Luigi Auriemma  Daniel Godas-Lopez  
    Alex Ionescu  jduck <jduck@metasploit.com>  #ms12-020
    
Basic options:  
    Name   Current Setting  Required  Description  
    ----   ---------------  --------  ----------  
    RHOST                   yes       The target address  
    RPORT  3389             yes       The target port

Description:  
    This module exploits the MS12-020 RDP vulnerability originally discovered and reported by Luigi Auriemma. 
    The flaw can be found in the way the T.125 ConnectMCSPDU packet is handled in the maxChannelIDs field, which will result an invalid pointer being used, therefore causing a denial-of-service condition.

```

### 工作原理

大多数漏洞扫描程序会通过评估多个不同的响应来尝试确定系统是否容易受特定攻击。 一些情况下，漏洞扫描可以简化为与远程服务建立TCP连接并且通过自我公开的特征，识别已知的漏洞版本。 在其他情况下，可以向远程服务发送一系列复杂的特定的探测请求，来试图请求对服务唯一的响应，该服务易受特定的攻击。 在前面的例子中，脚本的作者很可能找到了一种方法来请求唯一的响应，该响应只能由修补过或没有修补过的系统生成，然后用作确定任何给定的是否可利用的基础。
