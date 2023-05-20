AFL++可以用于对基于文件输入输出的二进制的模糊测试，而其本身无法对网络协议进行测试。这篇文章介绍了一种使用AFL++对固件网络程序进行模糊测试的方法。

本文参考于：[Fuzzing IoT binaries with AFL++ - Part II (attify.com)](https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/)

## 基本思路
这个是利用AFL++灰盒模糊测试工具结合[desockmulti](https://github.com/zyingp/desockmulti?ref=blog.attify.com)工具，desockmulti工具是一个用于hook socket套接字，将程序从网络获取数据流转变成从标准输入输出获取文件流，从而可以利用AFL++对固件网络进行协议模糊测试。

## 固件下载与仿真
这里以思科_RV130X_FW_1.0.3.55.bin固件为例，下载地址：
https://software.cisco.com/download/home/285026142/type/282465789/release/1.0.3.55

下载完后用binwalk解压得到文件系统，进入www目录，用qemu-arm-static模拟`usr/sbin/httpd`可以直接跑起来，-p指定运行的端口号为8081。
```
sudo ./qemu-arm-static -L .. ../usr/sbin/httpd -p 8081
sudo netstat -alnp | grep qemu
```

可以看到程序已经启动

![](images/Pasted%20image%2020230520101343.png)

这里我刚开始在运行的时候会报`Unknow QEMU_IFLA_BR type num`的警告，后来研究发现可能是qemu-arm-static的版本问题，后来我换成ubuntu 22.04用apt直接安装的6.2.0版本运行就没有这些警告了。有这些警告对程序的运行好像也没什么影响。

![](images/Pasted%20image%2020230520101425.png)

打开浏览器访问`http://127.0.0.1:8081` 

![](images/Pasted%20image%2020230520101558.png)

使用`admin:123456` 登录，用Burp Suite抓包

![](images/Pasted%20image%2020230520101725.png)

将该数据包保存为base-login-request.txt作为模糊测试的种子。

```
POST /login.cgi HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 139
Origin: http://127.0.0.1:8081
Connection: close
Referer: http://127.0.0.1:8081/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

submit_button=login&submit_type=&gui_action=&wait_time=0&change_action=&enc=1&continue_key=&user=admin&pwd=3ff83912fdb4176a21cd5c93e2094554
```

然后根据AFL++使用方法配置好AFL++和QEMU模式。

## patch httpd
在进行模糊测试前需要先对httpd进行一些patch。首先，httpd二进制文件目前使用daemon函数fork到后台，我们不希望在模糊测试期间出现这种fork行为（在main函数`sub_228AC()`中），所以需要patch daemon()让它直接返回0而不进行fork。

![](images/Pasted%20image%2020230520103217.png)

我们需要做的另一个改变是让httpd在退出前正好处理一个请求（不像一般的网络服务器那样无限期地处理请求）。这样，我们就可以知道哪个请求（如果有的话）会使网络服务器崩溃。

要关闭一个套接字，httpd调用close()函数。有三个地方可以调用close()。

![](images/Pasted%20image%2020230520103542.png)

其中，我们需要修改0x231c0位置的那个，让它调用exit(0)而不是close()

![](images/Pasted%20image%2020230520103942.png)

![](images/Pasted%20image%2020230520103956.png)

为了对程序进行patch，可以使用[Cutter](https://cutter.re/?ref=blog.attify.com)工具，这是一个免费开源的逆向工具，在对程序进行patch时，可以以直接修改指令的方式进行patch。进入界面后选择我们要分析的二进制程序

![](images/Pasted%20image%2020230520104420.png)

然后选择”以写入模式加载“，确定

![](images/Pasted%20image%2020230520104506.png)

然后它就开始进行分析，分析完后就进入了主界面，在上面输入框输入地址后按回车可以跳到对应地址处

![](images/Pasted%20image%2020230520104851.png)

双击`close`就进到了`0x106b4` 

![](images/Pasted%20image%2020230520104941.png)

`exit`函数的地址位于`0x10b64` 

![](images/Pasted%20image%2020230520105034.png)

所以我们要把`bl close`指令由`bl 0x106b4` 改为`bl 0x10b64`来调用`exit`函数。patch的方法是将光标放在`bl close`指令处，然后右键->编辑->指令。

![](images/Pasted%20image%2020230520105304.png)

同时，修改该指令的上一条指令来使`r0` 的值赋为0，我们将`mov r0, sl`改变为`eor r0, r0` 

![](images/Pasted%20image%2020230520105546.png)

![](images/Pasted%20image%2020230520105633.png)

这里我们将对`close()` 的调用改编为了对`exit()` 的调用，下面我们对位于`0x22cb4`处对`daemon` 的调用进行修改

![](images/Pasted%20image%2020230520105918.png)

我们直接把`bl daemon`指令变为`eor r0, r0`指令来时`r0` 直接赋0，使程序认为它已经调用成功。

![](images/Pasted%20image%2020230520110050.png)

最后保存：文件->提交更改，如果设置模式是写入模式的话原始应该已经修改好了，我们将修改后的程序命名为`httpd_patched` ，下面我们对patch过的程序进行测试。
```

```






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
```
QEMU_LD_PREFIX=.. QEMU_SET_ENV=USE_RAW_FORMAT=1,LD_PRELOAD=../desockmulti.so ~/Desktop/AFLplusplus/afl-fuzz -Q -i ../../input -o ../../output -- ../usr/sbin/httpd_patched2 -p 8081
```

![](images/Pasted%20image%2020230519220907.png)


## 其他问题
Burp Suite抓不到127.0.0.1的包：[(169条消息) 设置burpsuite抓取localhost、127.0.0.1数据,解决无法抓取拦截本机数据包_burpsuite怎么查localhost_陌兮_的博客-CSDN博客](https://blog.csdn.net/m0_47470899/article/details/119298514)


## 参考链接
[Fuzzing IoT binaries with AFL++ - Part I (attify.com)](https://blog.attify.com/fuzzing-iot-devices-part-1/)

[Fuzzing IoT binaries with AFL++ - Part II (attify.com)](https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/)
