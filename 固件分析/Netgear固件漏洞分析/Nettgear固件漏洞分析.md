## CVE-2020-27867
类型：命令注入
漏洞程序：mini_httpd->setup.cgi

### 漏洞点
命令位于`setup.cgi`程序`sub_407C80`程序中，读取`funjsq_access_token`参数后直接拼接到命令字符串中执行。

![](images/Pasted%20image%2020230821094354.png)

### 如何触发
`sub_407C80`是通过映射得到的，对于`funjsq_login`。

![](images/Pasted%20image%2020230821104018.png)

在main函数中，会获取传入的`todo`，存在才调用`CallActionByName()`，`CallActionByName()`路由映射关系，依次判断映射表和`todo`内容是否一样，一样就调用相应处理函数。

![](images/Pasted%20image%2020230821104730.png)

![](images/Pasted%20image%2020230821104715.png)

疑惑的是mini_httpd是如何触发到setup.cgi程序的呢？通过对漏洞关键字`funjsq_access_token`进行查找发现下面这条链：basic_wait.htm->basic_home.htm->basic.js->funjsq.htm。basic_wait.htm是一个到basic_home.htm的跳转，asic_home.htm里面使用了basic.js，basic.js`click_action()`中在`id == "funjsq"`时调用了`goto_formframe('funjsq.htm');`，funjsq.htm发起请求。而`id="funjsq"`index.htm中设置的一个菜单选项“游戏加速器”，点击会调用`click_action("funjsq")`。

前端静态页面里有很多`@***#`（如`@post_par#`）这样的东西，这应该是占位的，传到mini_httpd程序中进行解析用相应的值进行替换再返回给客户端。

参考：[CVE-2020-27867 NETGEAR 路由器 RCE 漏洞复现及简要分析-安全客](https://www.anquanke.com/post/id/259241)

## CVE-2021-27239
类型：栈溢出
程序：upnp
简介：upnp程序在解析SSDP协议时存在漏洞，没有对MX参数值进行判断，直接通过strncpy拷贝到栈上遍历，拷贝长度为参数长度。
### 漏洞点
在`sub_24B74`函数中对MX进行解析，24行将参数内容直接拷贝给v6。
（v3=v2为MX:...开始位置，v4为末尾位置，v3+3为参数值开始位置，v4-(v3+3)即为参数值长度）

![](images/Pasted%20image%2020230821111254.png)

### 如何触发
漏洞函数位于上层函数sub_25E04()中调用，该函数用于解析SSDP协议请求(SSDP数据包案例如下)

```
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 5
ST: ssdp:all
```

在调用漏洞函数前有一些要求，如设置`MAN: "ssdp:discover"`。

![](images/Pasted%20image%2020230821111828.png)

它的上层为sub_1D020()，（再上层为main），功能应该是启动处理upnp服务相关的，SSDP是构成UPnP技术的核心协议之一，所以里面包含处理SSDP协议请求的函数调用。会触发漏洞的函数调用位置如下。

![](images/Pasted%20image%2020230821112308.png)

触发：开启upnp服务，发送SSDP请求，设置MX超长参数值。

挖掘思路：这是SSDP协议漏洞，或UPNP？对固件中相关的协议进行模糊测试；静态审计危险函数。

疑惑：发送的poc为什么后面要加个`\x00`？

参考链接：

[CVE-2021-27239 漏洞复现 - xshhc - 博客园 (cnblogs.com)](https://www.cnblogs.com/xshhc/p/17365932.html)

[IoT：CVE-2021-27239复现记录 (toleleyjl.github.io)](https://toleleyjl.github.io/2023/04/09/CVE-2021-27239%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E8%AE%B0%E5%BD%95/)

