# Greenhouse Patch结果分析
以`AC1450_V1.0.0.6_1.0.3.chk`为例对Greenhouse工具跑出的结果进行分析，看一下docker是如何启动固件的，然后尝试不利用docker直接启动。

## 生成的文件分析
生成的文件目录如下：

![](images/Pasted%20image%2020231014212256.png)

### config.json
config.json文件里描述了关于这个设备仿真时的相关信息
```json
{
      "image": "AC1450_V1.0.0.6_1.0.3.chk",
      "hash": "eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995",
      "brand": "netgear",
      "result": "SUCCESS",
      "seconds_to_up": 204.39599227905273,
      "targetpath": "/usr/sbin/httpd",
      "targetip": "172.21.0.2",
      "targetport": "80",
      "ipv6enable": true,
      "env": {
            "LD_PRELOAD": "libnvram-faker.so"
      },
      "workdir": "/",
      "background": [
            [
                  "/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve \"/qemu-arm-static -hackbind -hackproc -hacksysinfo \" -E LD_PRELOAD=\"libnvram-faker.so\" /bin/sh /run_background.sh",
                  1
            ],
            [
                  "/run_setup.sh",
                  1
            ]
      ],
      "loginuser": "admin",
      "loginpassword": "password",
      "loginurl": "http://172.21.0.2:80",
      "logintype": "basic",
      "loginheaders": {
            "User-Agent": "python-requests/2.24.0",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="
      },
      "loginpayload": "",
      "qemuargs": {
            "hackbind": "",
            "hackproc": "",
            "hacksysinfo": "",
            "execve": "/qemu-arm-static -hackbind -hackproc -hacksysinfo"
      }
}
```
### debug目录
然后看debug目录，看Dockerfile文件内容如下，就是将fs拷贝到Ubuntu中然后执行run.debug.sh脚本。
```
FROM ubuntu:20.04
RUN apt-get update && apt-get -y install vim curl
COPY fs /fs
CMD ["./fs/run_debug.sh"]
```

查看docker-compose.yml文件，主要是配置网络和端口转发。

```yml
version: "2.2"

services:
  gh_rehosted:
    build: .
    privileged: true
    networks:
      eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge0:
        ipv4_address: 172.21.0.2
      eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge1:
        ipv4_address: 192.168.1.5
      eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge2:
        ipv4_address: 192.168.2.5
    ports:
      - 80:80/tcp
      - 80:80/udp
      - 81:81/tcp
      - 81:81/udp
      - 443:443/tcp
      - 443:443/udp

networks:
   eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge0:
     driver: bridge
     ipam:
       config:
       - subnet: 172.21.0.0/24
         gateway: 172.21.0.1
   eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge1:
     driver: bridge
     ipam:
       config:
       - subnet: 192.168.1.0/24
         gateway: 192.168.1.1
   eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge2:
     driver: bridge
     ipam:
       config:
       - subnet: 192.168.2.0/24
         gateway: 192.168.2.1
```

现在我们看fs中的启动脚本run_debug.sh，主要执行三个脚本：`run_setup.sh`，`run_background.sh`, `qemu_run.sh`。
```sh
#!/bin/sh
chroot /fs /run_setup.sh

chroot fs /qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /fs/GREENHOUSE_BGLOG 2>&1

chroot fs /qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /qemu_run.sh

while true; do sleep 10000; done
```

run_setup.sh脚本内容主要是执行setup_dev.sh脚本，这个脚本是设置/dev的一些配置。
```sh
#!/bin/sh
/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev
```

run_background.sh对于很多固件来说都是空的，暂不讨论。最后的qemu_run.sh脚本就是httpd的启动脚本。
```sh
/usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

所以总结起来就是，运行docker后运行run_debug.sh脚本，这个脚本依次运行`run_setup.sh`，`run_background.sh`, `qemu_run.sh`，功能就是先配置/dev，然后启动httpd程序。

### minimal目录
docker-compse.yml文件和debug目录中的一样，配置网络和端口转发，Dockerfile内容有变：


```
FROM scratch
ADD fs /

ENV LD_PRELOAD=libnvram-faker.so

EXPOSE 80/tcp
EXPOSE 80/udp
EXPOSE 1900/tcp
EXPOSE 1900/udp

ENTRYPOINT ["/greenhouse/busybox", "sh", "/run_clean.sh"]

CMD ["qemu-arm-static", "--", "/usr/sbin/httpd", "-S", "-E", "/usr/sbin/ca.pem", "/usr/sbin/httpsd.pem"]
```

run_clean.sh脚本内容：
```
#!/bin/sh

/run_setup.sh

/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /GREENHOUSE_BGLOG 2>&1

/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh qemu_run.sh
while true; do /greenhouse/busybox sleep 100000; done
```

奇怪，为什么感觉CMD命令和ENTRYPOINT脚本中的命令有重合，为什么要写两次？

## 手动执行仿真
首先执行下面命令，可以直接仿真成功
```
sudo chroot . greenhouse/busybox sh /run_clean.sh
```

然后尝试执行下面命令，访问不了web服务
```sh
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
# 或
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /bin/sh /qemu_run.sh
```

![](images/Pasted%20image%2020231014220044.png)

![](images/Pasted%20image%2020231014220107.png)

这中间的差别似乎就在于没用执行run_setup.sh进行/dev相关的配置，尝试执行下面指令，结果还是和原来一样不行。
```
sudo chroot . greenhouse/busybox sh
/run_setup.sh
/qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

然后把最后一条命令换成这个就可以了，真是奇怪。
```
/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

于是尝试这样运行，发现也是可以的，看来不是/dev的问题（但是不知道/dev配置对仿真有没有什么影响）。
```
sudo chroot . ./qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

![](images/Pasted%20image%2020231014221423.png)

这一系列参数的作用是什么，询问ChatGPT得到答案如下：
```
-qemu-arm-static：这是一个模拟ARM环境的静态二进制文件，它会在其后面跟随的命令中执行，并以模拟ARM环境的方式运行命令。

-hackbind：该选项将宿主机的目录和模拟环境的目录进行绑定，以便在ARM程序中访问宿主机上的文件。

-hackproc：该选项用于模拟ARM环境中进程的创建情况，避免因不同架构带来的兼容性问题。

-hacksysinfo：该选项用于模拟ARM环境中的系统信息，使得ARM程序可以正常地访问和查询系统相关信息。

-execve：该选项用于替代默认的execve系统调用，以支持特殊的环境变量和选项设置。

-E LD_PRELOAD="libnvram-faker.so"：该选项设置了一个名为LD_PRELOAD的环境变量，并将值设置为"libnvram-faker.so"，这个环境变量会告诉执行的程序在执行时需要加载指定的共享库。
```

我的理解是，-hackbin、-hackproc、-hacksyinfo设置目录、proc和系统信息等，使其更好的仿真，-evecve将execve替换为"/qemu-arm-static -hackbind -hackproc -hacksysinfo"，后面就是正常的仿真参数。
```
sudo chroot . ./qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo" -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

看起来这几个参数很厉害，加上去之后之前仿真不起来的也能直接仿真起来，但是之前从来都没见过有人这么用。经过查阅发现，这应该不是原来qemu-arm-static里面的参数，而是作者patch后的。项目位于：[SEFCOM/GHQEMU5 (github.com)](https://github.com/sefcom/ghqemu5)

这几个参数的准确作用如下：
- hackproc，复制/dev和/proc的内容，hack openat()系统调用来从那读
- hackbind，强制ipv6绑定ipv4上的0.0.0.0
- execve：添加一个参数，该参数指定 qemu-user-static 二进制文件的绝对路径，用于解决方法和调用，以便它们使用相同的 QEMU-user-static 二进制文件和传入相同的参数（否则，它默认为主机的 QEMU，即使安装了binfmt工具也可能导致问题）到`system()``execve()`
- hacksys：始终指示正在使用0个 CPU 资源的解决方法，以绕过由于系统限制而导致的行为更改，尤其是在模糊测试时

## ghqemu5源码分析
### sysinfo
涉及sysinfo的主要代码如下，switch在8565行

![](images/Pasted%20image%2020231014230824.png)

![](images/Pasted%20image%2020231014225122.png)

看源码感觉sysinfo改的没什么用，经测试，-hacksysinfo参数去掉确实对仿真没有影响，其次测试发现去掉-execve参数对仿真也没有影响，所以影响仿真最重要的两个参数是-hackbind和-hackproc。

```
sudo chroot . ./qemu-arm-static -hackbind -hackproc -execve "/qemu-arm-static -hackbind -hackproc " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem

sudo chroot . ./qemu-arm-static -hackproc -execve "/qemu-arm-static -hackproc " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

### hackbind
去掉-hackbind的结果如下，不能正常访问：

![](images/Pasted%20image%2020231014231658.png)

hackbind在syscall.c文件中有3处引用，似乎就是处理IPV6情况，转换为IPV4处理。

但是为什么需要处理IPV6的情况呢？查找提到的关键字发现就在httpd程序里出现过。

![](images/Pasted%20image%2020231014235233.png)

引用该字符串的位置如下，因为s1与"GET /shares"不同所以输出了这个字符串，那么s1是什么，dword_21BA04和fd是什么，为什么会跳到else这里。

![](images/Pasted%20image%2020231014235629.png)

else对应的if语句如下，通过inet_ntoa将IP地址转化为点分十进制，然后判断是否是Lan子网，也就是说跳到else是因为没有从Lan访问。

![](images/Pasted%20image%2020231014235948.png)

fd、dword_21B9AC、dword_9C320、dword_21B99C等应该是不同类型或接口开启的套接字的文件描述符，通过dword_21BA04与其比较可以知道数据从哪个类型传过来的，其中fd = sub_D618(80)。

![](images/Pasted%20image%2020231015001114.png)

![](images/Pasted%20image%2020231015001129.png)

所以这个sub_D618()的主要作用是开启IPV6监听，还有一个函数sub_D77C()专门用于开启IPV4监听。

从wan口过来，ipv6，。。


### hackproc
去掉-hackproc结果如下，也是不能访问

![](images/Pasted%20image%2020231014231801.png)

hackproc在syscall.c文件中只有1处引用，如图所示

![](images/Pasted%20image%2020231014232559.png)

这个函数在syscall.c文件中只有一处调用，在do_openat()函数中，所以在打开文件时通过parse_ghpath对打开的文件进行判断，如果是/proc或/dev下的文件，就让其打开/ghproc或/ghdev下的对对应文件。
> `do_openat()` 是 Linux 内核中用于处理 `openat()` 系统调用的函数。该系统调用是文件操作相关调用之一，用于打开或创建一个文件或目录，并返回其文件描述符。

![](images/Pasted%20image%2020231014232707.png)

经过查看，发现Greenhouse仿真后的ghdev文件夹中有内容，ghproc文件夹没有内容，所以对仿真影响比较大的是ghdev文件。但还是感觉很奇怪，如果是直接使用ghdev，那setup_dev.sh脚本有什么意义呢。/dev文件下的文件是什么东西，mknod又是什么。

mknod用于创建设备文件或管道，基本语法：
```
mknod [OPTIONS] <name> <type> [<major> <minor>]
```

如建立一个新的名叫`coffee`，主设备号为`12`和从设备号为`2`的设备文件：
```text
mknod /dev/coffee c 12 2
```

其中`-m`参数的作用：`--mode=MODE`设置文件的权限为`MODE`。

对于setup_dev.sh脚本中的命令`mknod -m 660 $DEV/mem c 1 1 &> /dev/null`来说，用于在 `$DEV/mem` 路径下创建一个权限为 `660` 的字符设备文件，设备的主设备号为 1，次设备号为 1。`&> /dev/null` 部分表示将命令的输出和错误信息都重定向到 `/dev/null`，即不显示输出和错误信息。

也就是说仿真的时候dev还是用的/ghdev目录，自己在仿真的时候由于dev目录没有配置好会导致仿真失败。

为什么使用了dev还是仿真不起来

```
sudo chroot . /greenhouse/busybox sh
/setup_dev.sh /greenhouse/busybox /dev
/qemu-arm-static -hackbind -execve "/qemu-arm-static -hackbind " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

```
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

## 20231101
复制能跑起来的gh_fs为fs-qemu作为标准发布的qemu仿真环境。
```bash
cp `which qemu-arm-static` ./
```

运行这个命令会错误，无论是标准qemu还是gh_qemu。
```bash
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

![](images/Pasted%20image%2020231014220044.png)

首先找到能使gh_qemu跑起来的命令
```bash
sudo chroot . ./qemu-arm-static -hackbind -hackproc -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```
缺少-hackproc出现这个错误

![](images/Pasted%20image%2020231014220044.png)

缺少-hackbind访问页面时会出现这个错误

![](images/Pasted%20image%2020231101095319.png)

### hackproc参数处理
首先解决dev的问题，我想要将ghdev作为实际运行的dev，并且采用hook的方式，这样可以将gh结果直接应用于其它程序上。编写hook.c

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

#define PATH_MAX	260

int open(const char *file, int oflag, ...)
{
    fprintf(stderr, "hook open func!!\n");
    char* result;
    char rpath[PATH_MAX+1];
    char redirected_path[PATH_MAX+1];

    memset(rpath, 0, PATH_MAX+1);
    memset(redirected_path, 0, PATH_MAX+1);

    result = realpath(file, rpath);
    if (result == NULL) {
        memset(rpath, 0, PATH_MAX+1);
        snprintf(rpath, PATH_MAX, "%s", file);
        snprintf(redirected_path, PATH_MAX, "%s", file);
    }
    if (strncmp(rpath, "/proc/", 6) == 0) {
        snprintf(redirected_path, PATH_MAX, "/ghproc/%s", rpath+6);
    }
    else if (strncmp(rpath, "/dev/", 5) == 0) {
        snprintf(redirected_path, PATH_MAX, "/ghdev/%s", rpath+5);
    }else{
        snprintf(redirected_path, PATH_MAX, "%s", file);
    }
    
    fprintf(stderr, "try call open %s-->%s!!\n", file, redirected_path);
    typeof(&open) orig = dlsym(RTLD_NEXT, "open");
	return orig(redirected_path, oflag);
}
```

交叉编译
```
/home/ubuntu/Desktop/Firmwares/Netgear/R7000-V1.0.11.100_10.2.100/_R7000-V1.0.11.100_10.2.100.chk.extracted/armv7-eabihf--uclibc--stable-2020.08-1/bin/arm-linux-gcc hook.c -o hook.so  -fPIC -shared -ldl
```

加入hook.so后运行，可以看到`-hookproc`参数的问题已经解决。

```bash
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so hook.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

![](images/Pasted%20image%2020231101102257.png)

### hackbind参数处理
正常跑起来长这样，这与上面相比就增加了几条Qemu输出的调试信息，根据信息，qemu做了使用自定义的绑定，将ipv6协议强制到ipv4 0.0.0.0上。

![](images/Pasted%20image%2020231101102715.png)

socket()调用时domain address families对应的数值

```c
// int socket(int domain, int type, int protocol);
/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* AppleTalk DDP 		*/
#define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_ATMPVC	8	/* ATM PVCs			*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
```

gh中关于hackbind的修改比较多，其中一个是将AF_INET6变为了AF_INET，不知道其它修改的作用是什么，我打算先对这个进行hook，看它的效果如何。继续在原来的hook.c代码上添加

```c
#include <sys/socket.h>

int socket(int domain, int type, int protocol)
{
    int fd;
    if (domain == AF_INET6) {
        // handle all ipv6 networking as ipv4
        fprintf(stderr, "hook socket!!\n");
        domain = AF_INET;
    }
    typeof(&socket) original_socket = dlsym(RTLD_NEXT, "socket");
    return original_socket(domain, type, protocol);
}
```

重新编译为hook.c，然后运行，结果如图所示，说明是在调用bind的时候出现了问题。

![](images/Pasted%20image%2020231101104646.png)

看了一下ghqemu patch的源码，我们还应该对bind时的地址进行hook，将ipv6地址变为ipv4地址。继续为hook.c添加代码

```c
#include <netinet/in.h>
#include <arpa/inet.h>

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    void* cust_addr = 0;
    unsigned short port = 0;
    char ip[INET6_ADDRSTRLEN+1] = "";
    long ret;
    
    if(((struct sockaddr*)addr)->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, ip, sizeof(ip));
        port = ntohs(((struct sockaddr_in*)addr)->sin_port);
        fprintf(stderr, "[hook bind AF_INET] IP: %s\n", ip);
        fprintf(stderr, "[hook bind AF_INET] PORT: %hu\n", port);
    }
    else if (((struct sockaddr*)addr)->sa_family == AF_INET6){
        cust_addr = alloca(sizeof(struct sockaddr_in));
        port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
        memset(((struct sockaddr_in*)cust_addr), 0, sizeof(struct sockaddr_in));
        fprintf(stderr, "[hook bind AF_INET6] Using custom bind, forcing ipv6 protocol to ipv4 on addr 0.0.0.0 port %d\n", port);
        inet_pton(AF_INET, "0.0.0.0", &((struct sockaddr_in*)cust_addr)->sin_addr);
        inet_ntop(AF_INET, &((struct sockaddr_in*)cust_addr)->sin_addr, ip, sizeof(ip));
        ((struct sockaddr_in*)cust_addr)->sin_port = htons(port);
        ((struct sockaddr_in*)cust_addr)->sin_family = AF_INET;
        addr = cust_addr;
        addrlen = sizeof(struct sockaddr_in);
        fprintf(stderr, "[hook bind AF_INET6] IPV6: 0.0.0.0\n");
        fprintf(stderr, "[hook bind AF_INET6] IPV6_PORT: %hu\n", (unsigned short)ntohs(((struct sockaddr_in*)addr)->sin_port));
    }

    typeof(&bind) original_bind = dlsym(RTLD_NEXT, "bind");
    ret = original_bind(sockfd, addr, addrlen);
    fprintf(stderr, "[hook bind] get_errno: %d\n", ret);
}
```

测试是可以访问http web服务了，不放图了。看控制台给出的信息好像是IPV6绑定为80端口，IPV4绑定到443端口。

![](images/Pasted%20image%2020231101113158.png)

后面又稍微完善了部分代码，最终的代码如下：

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    void* cust_addr = 0;
    unsigned short port = 0, newport = 0;
    unsigned short reuse = 0, retries = 0;
    char ip[INET6_ADDRSTRLEN+1] = "";
    long ret;
    int used_ports[512] = {0};
    int ports_index = 0;
    
    if(((struct sockaddr*)addr)->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, ip, sizeof(ip));
        port = ntohs(((struct sockaddr_in*)addr)->sin_port);
        fprintf(stderr, "[hook bind AF_INET] IP: %s\n", ip);
        fprintf(stderr, "[hook bind AF_INET] PORT: %hu\n", port);
    }
    else if(((struct sockaddr*)addr)->sa_family == AF_INET6){
        cust_addr = alloca(sizeof(struct sockaddr_in));
        port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
        memset(((struct sockaddr_in*)cust_addr), 0, sizeof(struct sockaddr_in));
        fprintf(stderr, "[hook bind AF_INET6] Using custom bind, forcing ipv6 protocol to ipv4 on addr 0.0.0.0 port %d\n", port);
        inet_pton(AF_INET, "0.0.0.0", &((struct sockaddr_in*)cust_addr)->sin_addr);
        inet_ntop(AF_INET, &((struct sockaddr_in*)cust_addr)->sin_addr, ip, sizeof(ip));
        ((struct sockaddr_in*)cust_addr)->sin_port = htons(port);
        ((struct sockaddr_in*)cust_addr)->sin_family = AF_INET;
        addr = cust_addr;
        addrlen = sizeof(struct sockaddr_in);
        fprintf(stderr, "[hook bind AF_INET6] IPV6: 0.0.0.0\n");
        fprintf(stderr, "[hook bind AF_INET6] IPV6_PORT: %hu\n", (unsigned short)ntohs(((struct sockaddr_in*)addr)->sin_port));
    }

    typeof(&bind) original_bind = dlsym(RTLD_NEXT, "bind");

    newport = port;
    retries = 0;
    while (retries < 3) {
        ret = original_bind(sockfd, addr, addrlen);
        // fprintf(stderr, "[hook bind] get_errno: %d\n", ret);
        if (!ret) {
            fprintf(stderr, "[hook bind] Successful Bind %d\n", (int)ret);
            used_ports[ports_index] = newport;
            ports_index = ports_index + 1;
            return ret;
        }
        if (newport <= 0) {
            if (((struct sockaddr*)addr)->sa_family == AF_INET6 || ((struct sockaddr*)addr)->sa_family == AF_INET) {
                fprintf(stderr, "[hook bind] Forcing port %d to 80 and retrying...", newport);
                newport = 80;
            }
        }
        else {
            newport = newport + 1;
            while(1) {
                reuse = 0;
                for (int i = 0; i < ports_index; i++) {
                    if (newport == used_ports[i]) {
                        newport = newport + 1;
                        reuse = 1;
                        break;
                    }
                }
                if(reuse == 0) {
                    break;
                }
            }
            fprintf(stderr, "[hook bind] bind failed, retrying with port %d\n", newport);
            retries = retries + 1;
        }
        ((struct sockaddr_in*)addr)->sin_port = htons(newport);
    }
}
```

### 最终运行
```
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so hook.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

![](images/Pasted%20image%2020231101142828.png)

