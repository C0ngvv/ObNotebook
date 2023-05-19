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

![](images/Pasted%20image%2020230514202235.png)

在它们之间，我们需要修改在`0x231c0` 位置的调用`exit(0)` 而不是`close` 。

根据文章上的内容进行hook。

## 出现的问题
使用`desockmulti`后，响应返回值变成了400，而不是200。

调试，使用`desockmulti` ·
```
# squashfs-root/www/
sudo qemu-arm-static -g 5556 -L .. -E USE_RAW_FORMAT=1 -E LD_PRELOAD=../desockmulti.so ../usr/sbin/httpd_patched -p 8081 < ../../base-login-request.txt
```

调试，不使用`desockmulti` 
```
# squashfs-root/www/
sudo qemu-arm-static -g 5555 -L .. ../usr/sbin/httpd_patched -p 8081
```

gdb调试
```
gdb-multiarch -q ./usr/sbin/httpd_patched
b fprintf
target remote :5555
```

复现结果与文章不太相同，文章使用`desockmulti` 后使用文件请求后返回值为200，而我的返回值为400，经过调试后发现因为`sub_1EEAC(v45)`返回值不同，正常与不正常响应分别进入了不同的分支。

![](images/Pasted%20image%2020230517165523.png)

进一步调试发现是因为该函数中的调用`nvram_match("http_from", "lan")` 返回值不同。

![](images/Pasted%20image%2020230517165722.png)

继续调试发现主函数`sub_228AC()`中，会根据`dword_A9984` 的值执行不同的关于`http_from`的nvram设置，正常响应会执行第一个if。所以`dword_A9984`值的不同导致了不同的响应。

![](images/Pasted%20image%2020230517170005.png)

该值由函数`sub_1E6E8()` 赋值，且该函数被调用很多次。

![](images/Pasted%20image%2020230517170351.png)

给sub_1E6E8()下断点
```
b *0x23634
b *0x23618
b *0x23600
b *0x23598
b *0x23658

b *0x1E6FC
```

后来调试发现不是前面的问题，而是后面这个函数里面的问题。它第二个参数传进了`&addr.sa_family` ，而这个值是前面`v19 = accept(dword_A9988, &addr, &addr_len);` 获取得到的，即客户端的地址结构，因为经过了hook，所以它的`sa_family`的值为`AFF_UNIX`即为1，而非正常判断的`AF_NAT` (2)和`AF_NAT6`(10)。所以后面会跳到错误的分支去。

![](images/Pasted%20image%2020230519211228.png)

![](images/Pasted%20image%2020230519211556.png)

进入到函数中后，v3即代表`sa_family` 的值(1)，不满足2和10就会跳到错误分支，而不会正常处理，从而导致后续出错。后来将22行给v3赋值处进行了patch，将2直接赋值给v3，就解决了这个问题。

![](images/Pasted%20image%2020230519211711.png)

总结，问题是因为patch后将套接字类型将`sa_family`的值给改变了，改成了`AF_UNIX` (1)，程序在对这个值进行判断时没有相应的解析就会出错。此外还发现`desockmulti.so`实现时没有实现`setsockopt()` 函数，而是直接返回0，这个也可能导致会程序不一致现象发生。

终于，fuzz起来了！！

![](images/Pasted%20image%2020230519220259.png)

## 其他问题
Burp Suite抓不到127.0.0.1的包：[(169条消息) 设置burpsuite抓取localhost、127.0.0.1数据,解决无法抓取拦截本机数据包_burpsuite怎么查localhost_陌兮_的博客-CSDN博客](https://blog.csdn.net/m0_47470899/article/details/119298514)


## 参考链接
[Fuzzing IoT binaries with AFL++ - Part I (attify.com)](https://blog.attify.com/fuzzing-iot-devices-part-1/)

[Fuzzing IoT binaries with AFL++ - Part II (attify.com)](https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/)
