这篇文章介绍使用AFL++模糊套接字的二进制文件。

## 固件下载与仿真
这里以思科_RV130X_FW_1.0.3.55.bin固件为例，下载地址：
https://software.cisco.com/download/home/285026142/type/282465789/release/1.0.3.55

下载完后用binwalk解压得到文件系统，进入www目录，用qemu-arm-static模拟`usr/sbin/httpd`.
```
sudo qemu-arm-static -L .. ../usr/sbin/httpd
sudo netstat -alnp | grep qemu
```

![](images/Pasted%20image%2020230514104837.png)

打开浏览器访问`http://127.0.0.1` 

![](images/Pasted%20image%2020230514104923.png)

使用Burp Suite用`admin:123456` 登录抓包

![](images/Pasted%20image%2020230514105830.png)

```
POST /login.cgi HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Origin: http://127.0.0.1
Connection: close
Referer: http://127.0.0.1/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

submit_button=login&submit_type=&gui_action=&wait_time=0&change_action=&enc=1&continue_key=&user=admin&pwd=3ff83912fdb4176a21cd5c93e2094554
```

配置好afl++和Qemu模式。


## 用AFL++进行模糊测试

为使用AFL++进行模糊测试，程序必须接收来自文件的输入。因此我们需要进行二进制水平的修改，通过patch汇编指令和`LD_PRELOAD` 技巧。Github上的[desockmulti](https://github.com/zyingp/desockmulti?ref=blog.attify.com)项目可以用于这个目的。

在使用这个[desockmulti](https://github.com/zyingp/desockmulti?ref=blog.attify.com) 前，我们需要进行一下修改。`httpd`二进制程序目前使用daemon函数fork到后台，在模糊测试期间，我们并不需要这个fork行为。

![](images/Pasted%20image%2020230507223855.png)

我们需要覆写`daemon`，使其在不fork 的情况下实际返回0。这可以通过LD_PRELOAD或patch汇编指令来实现。

我们需要做的另一个改变是让httpd在退出前只处理一个请求（不像一般的网络服务器那样无限期地处理请求）。这样，我们就可以知道哪个请求（如果有的话）会使网络服务器崩溃。

要关闭一个socket，`httpd`调用`close`函数。有三个地方调用close。






## 其他问题
Burp Suite抓不到127.0.0.1的包：[(169条消息) 设置burpsuite抓取localhost、127.0.0.1数据,解决无法抓取拦截本机数据包_burpsuite怎么查localhost_陌兮_的博客-CSDN博客](https://blog.csdn.net/m0_47470899/article/details/119298514)



## 参考链接
[Fuzzing IoT binaries with AFL++ - Part I (attify.com)](https://blog.attify.com/fuzzing-iot-devices-part-1/)

[Fuzzing IoT binaries with AFL++ - Part II (attify.com)](https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/)
