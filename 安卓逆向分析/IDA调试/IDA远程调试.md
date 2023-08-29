## IDA调试雷电模拟器
前期可能需要root权限，打开开发者模式，启动USB调试功能。

我的主机是x86_64，所以模拟器运行的是x86或x86_64结构而不是arm架构，将IDA目录下的`dbgsrv/android_x86_server`（32位）拷贝到模拟器的`/data/local/tmp/`目录下，添加可执行权限，也可以换个名字如`as`。

启动相关的应用服务，开启端口转发功能，将电脑上23946端口转发给手机23946端口，然后启动android_x86_server。

```
adb shell am start  -n com.zj.wuaipojie/.ui.ChallengeEight
adb forward tcp:23946 tcp:23946
adb shell "su -c './data/local/tmp/as'"
```

接着在IDA打开需要调试的程序，Debugger选择`Remote Linux debugger`，process option设置Hostname:127.0.0.1，端口为默认23946。

![](images/Pasted%20image%2020230829103342.png)

然后选择Attach to Process，选择相应的进程

![](images/Pasted%20image%2020230829103424.png)

设置好断点，点击上面绿色三角就可以运行了。

![](images/Pasted%20image%2020230829103521.png)

运行起来后，在手机上进行相关操作，让程序执行到断点处，然后就可以进行动态调试。F7 Step into; F8 Step over; F9 continue; Ctrl+F7 run until return; F4 run to cursor。调试到某一位置，鼠标移动到某个变量上就可以看这个变量的值。

参考链接：

[《安卓逆向这档事》十二、大佬帮我分析一下](https://www.52pojie.cn/thread-1809646-1-1.html)