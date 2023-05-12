原文链接：[CVE-2016-6909 Fortigate 防火墙 Cookie 解析漏洞复现及简要分析-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/252842#h2-0)

## 环境安装
参考链接：[【高级篇 / FortiGate-VM】(6.4) ❀ 02. 安装并启用 FortiGate VM ❀ FortiGate 防火墙_飞塔防火墙虚拟机_飞塔老梅子的博客-CSDN博客](https://blog.csdn.net/meigang2012/article/details/105246640)

在网上找到FGT_VM-v400-build0482下载，然后解压，双击`Fortigate-VM.orf` 用VMware打开

![](images/Pasted%20image%2020230512214210.png)

然后进行虚拟机设置，设置第一个网络适配器为VMnet8模式

![](images/Pasted%20image%2020230512214421.png)

设置好后运行虚拟机，账号为`admin` ，密码为空。进去后进行网络设置，ip要和VMnet8在同一个网段，然后主机和防火墙就能ping通了。
```
# 显示接口信息
show system interface
# 配置静态ip
config system interface
edit port1
set mode static
set ip 192.168.65.99/24
```

通过`fnsysctl`命令可以执行一些linux基本命令。
```
fnsysctl ls
```

## 漏洞分析






