# 第七章 Web 应用扫描

## 7.1 使用 Nikto 扫描 Web 应用

Nikto 是 Kali 中的命令行工具，用于评估 Web 应用的已知安全问题。Nikto 爬取目标站点并生成大量预先准备的请求，尝试识别应用中存在的危险脚本和文件。这个秘籍中，我们会讨论如何针对 Web 应用执行 Nikto，以及如何解释结果。

### 准备

为了使用 Nikto 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

和执行 Nikto 相关的复杂语法和用法，很大程度上取决于目标应用的本质。为了查看用法和语法的概览，使用`nikto -help`命令。在所提供的第一个例子中，我们对`google.com`进行扫描。`-host`参数可以用于指定需要扫描的目标的主机名称。`-port`选项定义了 Web 服务所运行的端口。`-ssl`选项告诉 Nikto 在扫描之前，与目标服务器建立 SSL/TLS 会话。

```
root@KaliLinux:~# nikto -host google.com -port 443 -ssl 
- Nikto v2.1.4 
-------------------------------------------------------------------------
+ Target IP:          74.125.229.161 
+ Target Hostname:    google.com 
+ Target Port:        443 
-------------------------------------------------------------------------
+ SSL Info:        Subject: /C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.com
                   Ciphers: ECDHE-RSA-AES128-GCM-SHA256                   
                   Issuer:  /C=US/O=Google Inc/CN=Google Internet Authority G2 
+ Start Time:         2014-03-30 02:30:10 
-------------------------------------------------------------------------
+ Server: gws 
+ Root page / redirects to: https://www.google.com/ 
+ Server banner has changed from gws to GFE/2.0, this may suggest a WAF or load balancer is in place 
                                  ** {TRUNCATED} **
```

作为替代，`-host`参数可以用于定义目标系统的 IP 地址。`-nossl`参数可以用于告诉 Nikto 不要使用任何传输层的安全。`-vhost`选项用于指定 HTTP 请求中的主机协议头的值。在多个虚拟主机名称托管在单个 IP 地址上的时候，这非常有用。看看下面的例子：

```
root@KaliLinux:~# nikto -host 83.166.169.228 -port 80 -nossl -vhost packtpub.com 
- Nikto v2.1.4
-------------------------------------------------------------------------
+ Target IP:          83.166.169.228 
+ Target Hostname:    packtpub.com 
+ Target Port:        80 
+ Start Time:         2014-03-30 02:40:29 
-------------------------------------------------------------------------
+ Server: Varnish 
+ Root page / redirects to: http://www.packtpub.com/ 
+ No CGI Directories found (use '-C all' to force check all possible dirs) 
+ OSVDB-5737: WebLogic may reveal its internal IP or hostname in the Location header. The value is "http://www.packtpub.com." 
```

在上面的例子中，Nikto 对 Metasploitable2 系统上托管的 Web 服务执行了扫描。`-port`参数没有使用，因为 Web 服务托管到 TCP 80 端口上，这是 HTTP 的默认端口。此外，`-nossl`参数也没有使用，因为通常 Nikto 不会尝试 80 端口上的 SSL/TLS 连接。考虑下面的例子：

```
root@KaliLinux:~# nikto -host 172.16.36.135 
- Nikto v2.1.4 
-------------------------------------------------------------------------
+ Target IP:          172.16.36.135 
+ Target Hostname:    172.16.36.135 
+ Target Port:        80 
+ Start Time:         2014-03-29 23:54:28 
-------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) DAV/2 
+ Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.10 
+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.2.17). Apache 1.3.42 (final release) and 2.0.64 are also current. 
+ DEBUG HTTP verb may show server debugging information. See http://msdn. microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details. 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3233: /phpinfo.php: Contains PHP configuration information 
+ OSVDB-3268: /doc/: Directory indexing found. 
+ OSVDB-48: /doc/: The /doc/ directory is browsable. This may be /usr/ doc. 
+ OSVDB-12184: /index.php?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings. 
+ OSVDB-3092: /phpMyAdmin/: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts. 
+ OSVDB-3268: /test/: Directory indexing found. 
+ OSVDB-3092: /test/: This might be interesting... 
+ OSVDB-3268: /icons/: Directory indexing found. 
+ OSVDB-3233: /icons/README: Apache default file found. 
+ 6448 items checked: 1 error(s) and 13 item(s) reported on remote host 
+ End Time:           2014-03-29 23:55:00 (32 seconds) 
-------------------------------------------------------------------------
+ 1 host(s) tested
```

Nikto 的 Metasploitable2 扫描结果展示了一些经常被 Nikto 识别的项目。这些项目包括危险的 HTTP 方法，默认的安装文件，暴露的目录列表，敏感信息，以及应该被限制访问的文件。注意这些文件通常对于获取服务器访问以及寻找服务器漏洞很有帮助。

### 工作原理

Nikto 识别潜在的可疑文件，通过引用`robots.txt`，爬取网站页面，以及遍历包含敏感信息、漏洞内容，或者由于内容的本质或所表现的功能而应该被限制的已知文件列表。

## 7.2 使用 SSLScan 扫描 SSL/TLS

SSLScan 是 Kali 中的完整的命令行工具，用于评估远程 Web 服务的 SSL/TLS 的安全性。这个秘籍中，我们会讨论如何对 Web 应用执行 SSLScan，以及如何解释或操作输出结果。

### 准备

为了使用 SSLScan 对目标执行 SSL/TLS 分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

SSLScan 是个高效的工具，用于对目标 Web 服务执行精简的 SSL/TLS 配置分析。为了对带有域名 Web 服务执行基本的扫描，只需要将域名作为参数传递给它，就像这样：

```
root@KaliLinux:~# sslscan google.com
                   _
           ___ ___| |___  ___ __ _ _ __ 
          / __/ __| / __|/ __/ _` | '_ \
          \__ \__ \ \__ \ (_| (_| | | | |
          |___/___/_|___/\___\__,_|_| |_|
                  
                  Version 1.8.2
            http://www.titania.co.uk
       Copyright Ian Ventura-Whiting 2009
       
Testing SSL server google.com on port 443  
  Supported Server Cipher(s):    
    Failed    SSLv3  256 bits  ECDHE-RSA-AES256-GCM-SHA384    
    Failed    SSLv3  256 bits  ECDHE-ECDSA-AES256-GCM-SHA384    
    Failed    SSLv3  256 bits  ECDHE-RSA-AES256-SHA384    
    Failed    SSLv3  256 bits  ECDHE-ECDSA-AES256-SHA384    
    Accepted  SSLv3  256 bits  ECDHE-RSA-AES256-SHA    
    Rejected  SSLv3  256 bits  ECDHE-ECDSA-AES256-SHA    
    Rejected  SSLv3  256 bits  SRP-DSS-AES-256-CBC-SHA    
    Rejected  SSLv3  256 bits  SRP-RSA-AES-256-CBC-SHA    
    Failed    SSLv3  256 bits  DHE-DSS-AES256-GCM-SHA384    
    Failed    SSLv3  256 bits  DHE-RSA-AES256-GCM-SHA384
    Failed    SSLv3  256 bits  DHE-RSA-AES256-SHA256    
    Failed    SSLv3  256 bits  DHE-DSS-AES256-SHA256    
    Rejected  SSLv3  256 bits  DHE-RSA-AES256-SHA    
    Rejected  SSLv3  256 bits  DHE-DSS-AES256-SHA    
    Rejected  SSLv3  256 bits  DHE-RSA-CAMELLIA256-SHA    
    Rejected  SSLv3  256 bits  DHE-DSS-CAMELLIA256-SHA 
                            ** {TRUNCATED} **
```

在执行时，SSLScan 会快速遍历目标服务器的连接，并且枚举所接受的密文，首选的密文族，以及 SSL 证书信息。可以用`grep`在输出中寻找所需信息。在下面的例子中，`grep`仅仅用于查看接受的密文。

```
root@KaliLinux:~# sslscan google.com | grep Accepted    
    Accepted  SSLv3  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  SSLv3  256 bits  AES256-SHA    
    Accepted  SSLv3  168 bits  ECDHE-RSA-DES-CBC3-SHA    
    Accepted  SSLv3  168 bits  DES-CBC3-SHA    
    Accepted  SSLv3  128 bits  ECDHE-RSA-AES128-SHA    
    Accepted  SSLv3  128 bits  AES128-SHA    
    Accepted  SSLv3  128 bits  ECDHE-RSA-RC4-SHA    
    Accepted  SSLv3  128 bits  RC4-SHA    
    Accepted  SSLv3  128 bits  RC4-MD5    
    Accepted  TLSv1  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  TLSv1  256 bits  AES256-SHA    
    Accepted  TLSv1  168 bits  ECDHE-RSA-DES-CBC3-SHA    
    Accepted  TLSv1  168 bits  DES-CBC3-SHA    
    Accepted  TLSv1  128 bits  ECDHE-RSA-AES128-SHA    
    Accepted  TLSv1  128 bits  AES128-SHA    
    Accepted  TLSv1  128 bits  ECDHE-RSA-RC4-SHA    
    Accepted  TLSv1  128 bits  RC4-SHA    
    Accepted  TLSv1  128 bits  RC4-MD5 
```

多个`grep`函数可以进一步过滤输出。通过使用多个`grep`管道请求，下面例子中的输出限制为 256 位密文，它可以被服务器接受。

```
root@KaliLinux:~# sslscan google.com | grep Accepted | grep "256 bits"    
    Accepted  SSLv3  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  SSLv3  256 bits  AES256-SHA
    Accepted  TLSv1  256 bits  ECDHE-RSA-AES256-SHA    
    Accepted  TLSv1  256 bits  AES256-SHA
```

SSLScan 提供的一个独特的功能就是 SMTP 中的`STARTTLS `请求的实现。这允许 SSLScan 轻易并高效地测试邮件服务的传输安全层，通过使用`--starttls `参数并随后指定目标 IP 地址和端口。下面的例子中，我们使用 SSLScan 来判断 Metasploitable2 所集成的 SMTP 服务是否支持任何脆弱的 40 位密文：

```
root@KaliLinux:~# sslscan --starttls 172.16.36.135:25 | grep Accepted | grep "40 bits"    
    Accepted  TLSv1  40 bits   EXP-EDH-RSA-DES-CBC-SHA    
    Accepted  TLSv1  40 bits   EXP-ADH-DES-CBC-SHA    
    Accepted  TLSv1  40 bits   EXP-DES-CBC-SHA    
    Accepted  TLSv1  40 bits   EXP-RC2-CBC-MD5    
    Accepted  TLSv1  40 bits   EXP-ADH-RC4-MD5    
    Accepted  TLSv1  40 bits   EXP-RC4-MD5
```

## 工作原理

SSL/TLS 会话通常通过客户端和服务端之间的协商来建立。这些协商会考虑到每一端配置的密文首选项，并且尝试判断双方都支持的最安全的方案。SSLScan 的原理是遍历已知密文和密钥长度的列表，并尝试使用每个配置来和远程服务器协商会话。这允许 SSLScan 枚举受支持的密文和密钥。
