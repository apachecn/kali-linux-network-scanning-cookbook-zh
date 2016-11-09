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

SSLScan 是 Kali 中的集成命令行工具，用于评估远程 Web 服务的 SSL/TLS 的安全性。这个秘籍中，我们会讨论如何对 Web 应用执行 SSLScan，以及如何解释或操作输出结果。

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

### 工作原理

SSL/TLS 会话通常通过客户端和服务端之间的协商来建立。这些协商会考虑到每一端配置的密文首选项，并且尝试判断双方都支持的最安全的方案。SSLScan 的原理是遍历已知密文和密钥长度的列表，并尝试使用每个配置来和远程服务器协商会话。这允许 SSLScan 枚举受支持的密文和密钥。

## 7.3 使用 SSLyze 扫描 SSL/TLS

SSLyze 是 Kali 中的集成命令行工具，用于评估远程 Web 服务的 SSL/TLS 的安全性。这个秘籍中，我们会讨论如何对 Web 应用执行 SSLyze，以及如何解释或操作输出结果。

### 准备

为了使用 SSLScan 对目标执行 SSL/TLS 分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

### 操作步骤

另一个用于对 SSL/TLS 配置执行彻底排查和分析的工具就是 SSLyze。为了使用 SSLyze 执行基本的测试，需要包含目标服务器作为参数，以及`--regular`参数。这包括 SSLv2、SSLv3、TLSv1、renegotiation、resumption、证书信息、HTTP GET 响应状态码，以及压缩支持的测试。

```
root@KaliLinux:~# sslyze google.com --regular

 REGISTERING AVAILABLE PLUGINS 
 ----------------------------

 PluginSessionResumption  
 PluginCertInfo  
 PluginOpenSSLCipherSuites  
 PluginSessionRenegotiation  
 PluginCompression

 CHECKING HOST(S) AVAILABILITY 
 ----------------------------
 
   google.com:443                      => 74.125.226.166:443
   
 SCAN RESULTS FOR GOOGLE.COM:443 - 74.125.226.166:443 ---------------------------------------------------
 
  * Compression :
        Compression Support:      Disabled
        
  * Certificate :      
      Validation w/ Mozilla's CA Store:  Certificate is Trusted                   
      Hostname Validation:               OK - Subject Alternative Name Matches      
      SHA1 Fingerprint:                  EF8845009EED2B2FE95D23318C8CF30F1052B596
      Common Name:                       *.google.com                             
      Issuer:                            /C=US/O=Google Inc/CN=Google Internet Authority G2      Serial 
      Number:                     5E0EFAF2A99854BD                         Not 
      Before:                        Mar 12 09:53:40 2014 GMT                 
      Not After:                         Jun 10 00:00:00 2014 GMT                 
      Signature Algorithm:               sha1WithRSAEncryption                    
      Key Size:                          2048                                     
      X509v3 Subject Alternative Name:   DNS:*.google.com, DNS:*. android.com, DNS:*.appengine.google.com, DNS:*.cloud.google.com, DNS:*. google-analytics.com, DNS:*.google.ca, DNS:*.google.cl, DNS:*.google. co.in, DNS:*.google.co.jp, DNS:*.google.co.uk, DNS:*.google.com.ar, DNS:*.google.com.au, DNS:*.google.com.br, DNS:*.google.com.co, DNS:*. google.com.mx, DNS:*.google.com.tr, DNS:*.google.com.vn, DNS:*.google. de, DNS:*.google.es, DNS:*.google.fr, DNS:*.google.hu, DNS:*.google. it, DNS:*.google.nl, DNS:*.google.pl, DNS:*.google.pt, DNS:*.googleapis. cn, DNS:*.googlecommerce.com, DNS:*.googlevideo.com, DNS:*.gstatic.com, DNS:*.gvt1.com, DNS:*.urchin.com, DNS:*.url.google.com, DNS:*.youtubenocookie.com, DNS:*.youtube.com, DNS:*.youtubeeducation.com, DNS:*.ytimg. com, DNS:android.com, DNS:g.co, DNS:goo.gl, DNS:google-analytics.com, DNS:google.com, DNS:googlecommerce.com, DNS:urchin.com, DNS:youtu.be, DNS:youtube.com, DNS:youtubeeducation.com 
                                  ** {TRUNCATED} **
```

作为替代，TLS 或者 SSL 的单个版本可以被测试来枚举和版本相关的所支持的密文。下面的例子中，SSLyze 用于枚举受 TLSv1.2 支持的密文，之后使用`grep`来提取出 256 位的密文。

```
root@KaliLinux:~# sslyze google.com --tlsv1_2 | grep "256 bits"        
    ECDHE-RSA-AES256-SHA384  256 bits                                                 
    ECDHE-RSA-AES256-SHA     256 bits                                                 
    ECDHE-RSA-AES256-GCM-SHA384256 bits                                                 
    AES256-SHA256            256 bits                                                 
    AES256-SHA               256 bits                                                 
    AES256-GCM-SHA384        256 bits
```

SSLyze 支持的一个非常拥有的特性是 Zlib 压缩的测试。如果开启了压缩，会直接关系到信息列楼漏洞，被称为`Compression Ratio Info-leak Made Easy`（CRIME）。这个测试可以使用`--comprision`参数来执行：

```
root@KaliLinux:~# sslyze google.com --compression
 
 CHECKING HOST(S) AVAILABILITY
 ----------------------------
   
   google.com:443                      => 173.194.43.40:443
 
 SCAN RESULTS FOR GOOGLE.COM:443 - 173.194.43.40:443 --------------------------------------------------
  
  * Compression :        Compression Support:      Disabled 
                                             ** {TRUNCATED} **
```

### 工作原理

SSL/TLS 会话通常通过客户端和服务端之间的协商来建立。这些协商会考虑到每一端配置的密文首选项，并且尝试判断双方都支持的最安全的方案。SSLyze 的原理是遍历已知密文和密钥长度的列表，并尝试使用每个配置来和远程服务器协商会话。这允许 SSLyze 枚举受支持的密文和密钥。

## 7.4 使用 BurpSuite 确定 Web 应用目标

在执行渗透测试的时候，确保你的攻击仅仅针对目标系统非常重要。针对额外目标的攻击可能导致法律问题。为了使损失最小，在 Burp Suite 中确定你的范围十分重要。这个秘籍中，我们会讨论如何使用 BurpSuite 确定范围内的目标。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

BurpSuite 的最左边的标签页就是`Target`。这个标签页的底下有两个标签页，包括`Site Map`和`Scope`。在通过设置代理的 Web 浏览器访问时，`SiteMap`标签页会自动填充。`Scope`标签页允许用户配置站点和其内容，来包含或者排除站点。为了向评估范围内添加新的站点，点击`Include in Scope`表格下的`Add`按钮。像这样：

![](img/7-4-1.jpg)

所添加的内容通常是 IP 地址范围，或者由单独的文件指定。`Protocal`选项会显示下拉菜单，包含 ANY、HTTP、HTTPS。`Host or IP range`字段可以包含单个主机名称，单个 IP，或者 IP 范围。此外，也存在`Port`和`File`的文本字段。字段可以留空，或者用于指定范围。字段应该使用正则表达式来填充。在所提供的例子中，脱字符（`^`）是正则表达式的开始，美元符号用于闭合正则表达式，反斜杠用于转移特殊字符`.`，它用于分隔 IP 地址的段。正则表达式的用法并不在本书的范围内，但是许多互联网上的开放资源都解释了它们的用法。你可以访问`http://www.regularexpressions.info/`来熟悉一下正则表达式。

### 工作原理

正则表达式在逻辑上定义条件，通过指定主机、端口或范围中包含的文件。定义评估范围会影响它在和 Web 内容交互时的操作方式。BurpSuite 配置定义了可以执行什么操作，它们位于范围内，以及什么不能执行，它们在范围之外。

## 7.5 使用 BurpSuite 蜘蛛

为了有效供给 Web 应用，了解服务器上所托管的 Web 内容非常重要。可以使用做种技巧来探索 Web 应用的整个攻击面。蜘蛛工具可以用于快速识别 Web 应用中引用的链接内容。这个秘籍中，我们会谈论如何使用 BurpSuite 爬取 Web 应用来识别范围内的内容。

### 准备

为了使用 BurpSuite 对目标执行 Web 应用分析，你需要拥有运行一个或多个 Web 应用的远程系统。所提供的例子中，我们使用 Metasploitable2 实例来完成任务。 Metasploitable2 拥有多种预安装的漏洞 Web 应用，运行在 TCP 80 端口上。配置 Metasploitable2 的更多信息请参考第一章中的“安装 Metasploitable2”秘籍。

此外，你的 Web 浏览器需要配置来通过 BurpSuite 本地实例代理 Web 流量。关于将 BurpSuite 用作浏览器代理的更多信息，请参考第一章的“配置 BurpSuite”一节。

### 操作步骤

为了自动化爬取之前定义的范围内的内容，点击屏幕顶端的`Spider`标签页。下面会有两个额外的标签页，包括`Control`和`Options`。`Options`标签页允许用户配置蜘蛛如何指定。这包括详细设置、深度、限制、表单提交以及其它。考虑自动化蜘蛛的配置非常重要，因为它会向范围内的所有 Web 内容发送请求。这可能会破坏甚至是损坏一些 Web 内容。一旦拍治好了，`Control`标签页可以用于选择开始自动化爬取。通常，`Spider`标签页是暂停的，点击按钮可以启动蜘蛛。`Target`标签页下面的`Site Map`标签页会在蜘蛛爬取过程中自动更新。像这样：

![](img/7-5-1.jpg)

取决于所定义的配置，对于任何爬取过程中碰到的表单，BurpSuite 会请求你的反应。输入表单需要的参数，或者通过`Ignore Form`按钮来跳过表单，像这样：

![](img/7-5-2.jpg)

作为替代，你可以通过右击`Site Map`标签页中的爬取特定位置，之后点击`Spider`，从特定位置开始爬取。这会递归爬取所选对象以及所包含的任何文件或目录。像这样：

![](img/7-5-3.jpg)

### 工作原理

BurpSuite 蜘蛛工具的工作原理是解析所有已知的 HTML 内容，并提取指向其它内容的链接。链接内容随后会用于分析所包含的其它链接内容。这个过程会无限继续下去，并只由可用的链接内容总数，指定的深度，以及处理额外请求的当前线程数量所限制。
