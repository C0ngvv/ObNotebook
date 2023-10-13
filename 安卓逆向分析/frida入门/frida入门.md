# frida入门
frida是安卓逆向非常有用的工具，作为一名新手，这里介绍一下它最简单的使用和Demo，学习工具使用的大致流程。这里先放上吾爱破解上看到的一张图。

![](images/frida教程.png)

## 1.环境安装
1.安装frida

```
pip install frida
pip install frida-tools
```

2.下载frida-server：[Releases · frida/frida (github.com)](https://github.com/frida/frida/releases)

![](images/Pasted%20image%2020231013101403.png)

## 2.android端环境配置
1.查看设备CPU架构
```
adb shell getprop ro.product.cpu.abi
```

2.将frida服务端推到手机的/data/local/tmp目录，并修改权限
```
adb push frida-server-16.1.4-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 777 /data/local/tmp/frida-server
```

3.启动服务端
```
adb shell 'su -c /data/local/tmp/frida-server'
```
## 3.hook注入
如将hook代码保存为hook.js，然后运行目标APP，执行下面命令，APP返回桌面再打开APP发现就能实现预期功能，输入exit停止注入。

```
frida -U -l hook.js com.luoyesiqiu.crackme
```

## 4.案例Demo
以[CrackMe challenges for Android](https://persianov.net/crackme-challenges-for-android)中的Crackme_0x01为例简单测试frida，我操作时所使用的环境如下：

```
frida==16.1.3
frida-tools==12.2.1
frida-server-16.1.4-android-x86_64
雷电模拟器（安卓9.0（64位））
```

打开程序后要求输入password提交，验证成功返回flag，失败会提示Wrong password

![](images/Pasted%20image%2020231013163134.png)

![](images/Pasted%20image%2020231013163258.png)

在jadx中打开安装包，搜索关键字"Wrong password"，发现程序是将用户输入内容作为参数调用`FlagGuard().getFlag(editText.getText().toString())`，若能得到返回值则输出flag。

![](images/Pasted%20image%2020231013163533.png)

双击进入`GlagGuard.getFlag()`函数，它的功能是将用户字符串和`Data().getData()`得到的字符串进行比较，一致就返回flag值。

![](images/Pasted%20image%2020231013163810.png)

为了使用frida，我们对`Data().getData()`方法进行Hook，编写hook.js，hook getData()方法让其直接返回"123"，如果我们在输入框输入123后能得到flag则说明hook成功。

```
if(Java.available){
    Java.perform(function(){
        var DataClass = Java.use("com.entebra.crackme0x01.Data");
        DataClass.getData.overload().implementation=function(){
            return "123";        
        }
    });
}
```

使用`frida-ps -U`命令查看进程名为`'CrackMe 0x01'`

![](images/Pasted%20image%2020231013164105.png)

在模拟器中启动程序，然后使用下面命令注入：

```
frida -U -l .\hook.js 'CrackMe 0x01'
```

（若要退出，输入exit）

![](images/Pasted%20image%2020231013164245.png)

退出程序，然后再进入，输入123验证，可以成功得到flag值，说明注入成功。

![](images/Pasted%20image%2020231013164303.png)


## 参考链接

[是时候来了解frida的用法了--Hook Java代码篇 - 『移动安全区』 - 吾爱破解](https://www.52pojie.cn/thread-931872-1-1.html)

[frida-dexdump脱壳工具简单使用的思维导图](https://www.52pojie.cn/forum.php?mod=viewthread&tid=1614476&extra=page%3D1%26filter%3Dtypeid%26typeid%3D343)
