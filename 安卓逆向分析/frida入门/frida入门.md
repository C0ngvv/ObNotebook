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

## 3.



## 参考链接

[是时候来了解frida的用法了--Hook Java代码篇 - 『移动安全区』 - 吾爱破解](https://www.52pojie.cn/thread-931872-1-1.html)
