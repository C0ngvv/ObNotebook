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
```shell
# 启动服务
sudo ./qemu-arm-static -L .. ../usr/sbin/httpd_patched -p 8081
# 在另一个终端用curl访问
curl http://127.0.0.1:8081 | head
```

可以看到，当我们使用curl进行访问后，程序就自动关闭了。

![](images/Pasted%20image%2020230520111113.png)

## 配置desockmulti
工具地址：[zyingp/desockmulti](https://github.com/zyingp/desockmulti?ref=blog.attify.com)

这个工具是论文[MultiFuzz](https://www.mdpi.com/1424-8220/20/18/5194/pdf)提供的一个工具，它利用LD_PRELOAD对程序与socket相关的函数进行hook，从而将网络数据流转变为标准输入输出，进而可以使用AFL++进行模糊测试。

### 编译
我们需要使用一个ARM交叉编译器来编译desockmulti。来自bootlin的[armv7-eabihf-uclibc](https://toolchains.bootlin.com/?ref=blog.attify.com)工具链对这一目的非常有效。我们需要使用一个基于uclibc的工具链，因为固件的二进制文件也使用相同的工具链。在/usr/bin/httpd上运行文件命令，指出二进制文件是动态链接到ld-uClibc的。我下载的工具链接为：[armv7-eabihf--uclibc--stable-2020.08-1](https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--uclibc--stable-2020.08-1.tar.bz2)

![](images/Pasted%20image%2020230520112034.png)

在对desockmulti进行编译前，需要对它的源码进行轻微改变：将453行对`setup_timer()` 函数的调用注释掉。

![](images/Pasted%20image%2020230520112518.png)

然后在desockmulti目录下运行命令进行编译，然后将`desockmulti.so` 复制到squashfs-root目录下。
```shell
make CC=~/Desktop/armv7-eabihf--uclibc--stable-2020.08-1/bin/arm-linux-gcc
```

### 测试desockmulti
为了测试desockmulti是否真的如预期那样工作，我们可以用gdb-multiarch调试httpd。因为desockmulti使用线程，而httpd默认不链接libpthread，因此我们需要用`patchelf` 添加一个到libpthread.so.0库的依赖项。`patchelf` 可以用apt安装。
```shell
patchelf --add-needed ./lib/libpthread.so.0 ./usr/sbin/httpd_patched
```

在终端1输入下面命令，使用desockmulti.so启动http_patched并将base-login-request.txt文件内容传递给程序。
```
sudo ./qemu-arm-static -g 5555 -L .. -E USE_RAW_FORMAT=1 -E LD_PRELOAD=../desockmulti.so ../usr/sbin/httpd_patched -p 8081 < ../../base-login-request.txt
```

然后在另一个终端启动`gdb-multiarch`调试
```shell
gdb-multiarch -q ./usr/sbin/httpd_patched
(gdb)
b fprintf
target remote :5555
```

给`fprintf`下断点，然后按`c` 运行，每次到断点时检测寄存器`r2`的值。按照参考的文章介绍，`r2`寄存器会出现`HTTP/1.1 200 Ok\r\n`的情况，即HTTP响应的第一行，可以证明desockmulti在起作用。但我在调试的时候没有出现200，而是得到了400：`HTTP/1.1 400 Bad Request (10)\r\n'`。

![](images/Pasted%20image%2020230520114124.png)

出现这种不一致的原因我后面会进行分析，但在这里出现这个字符串也可以证明`desockmulti` 起作用了。

## 进一步改进：权限问题
目前运行程序需要管理员权限，不然的话会提示`/var/run/httpd.pid` 没有权限。
```shell
./qemu-arm-static -L .. -E USE_RAW_FORMAT=1 -E LD_PRELOAD=../desockmulti.so ../usr/sbin/httpd_patched -p 8081 < ../../base-login-request.txt
```

![](images/Pasted%20image%2020230520115043.png)

利用hex编辑器，将`/var/run/httpd.pip` 修改为不需要管理员权限访问的`/home/ubuntu/h.pid` ，需要注意的是替换的字符串的长度必须小于或等于原始字符串。

![](images/Pasted%20image%2020230523170210.png)

修改后的结果如下：

![](images/Pasted%20image%2020230523170301.png)

此时再运行程序就不会提示权限问题了。

![](images/Pasted%20image%2020230523170425.png)

## 不一致的原因分析
到此，还有一个问题没有解决，就是原文使用`desockmulti.so` 后执行结果是200，而我的执行结果是400，和正常通过网络执行结果200不一致，这是怎么回事？起初怀疑是自己哪一步少操作了或是环境问题，仔细研究原文与改变环境后发现不是这个问题，后来经过两天的调试分析，终于找到了问题所在。

调试的命令，使用`desockmulti` 

```
# squashfs-root/www/
sudo ./qemu-arm-static -g 5556 -L .. -E USE_RAW_FORMAT=1 -E LD_PRELOAD=../desockmulti.so ../usr/sbin/httpd_patched -p 8081 < ../../base-login-request.txt
```

调试，不使用`desockmulti` 
```
# squashfs-root/www/
sudo ./qemu-arm-static -g 5555 -L .. ../usr/sbin/httpd_patched -p 8081
```

gdb调试
```
gdb-multiarch -q ./usr/sbin/httpd_patched
b fprintf
target remote :5555
```

最初经过调试后发现因为`sub_1EEAC(v45)`返回值不同，正常与不正常响应分别进入了不同的分支。

![](images/Pasted%20image%2020230517165523.png)

进入该函数进一步调试发现是因为该函数中的调用`nvram_match("http_from", "lan")` 返回值不同：网络方式的返回为0，而使用`desockmulti`后返回不为0，从而会执行if中语句返回负值，进而上层返回400错误。

![](images/Pasted%20image%2020230517165722.png)

后来就寻找给`http_from` 赋值的地方，调试发现主函数`sub_228AC()`中，会根据`dword_A9984` 等变量值执行不同的关于`http_from`的nvram设置，正常响应会执行第一个if。

![](images/Pasted%20image%2020230517170005.png)

刚开始以为是这个变量值的问题，于是去找到给这些变量赋值的地方，它们由函数`sub_1E6E8()` 赋值，且该函数被调用很多次。

![](images/Pasted%20image%2020230517170351.png)

这个函数是用来建立套接字、绑定监听的，

```c
int __fastcall sub_1E6E8(const struct sockaddr *a1)
{
  int sa_family; // r0
  FILE *v3; // r0
  FILE *v4; // r4
  int v5; // r5
  int v7; // r0
  int v8; // r2
  int v9; // r2
  socklen_t v10; // r2
  int optval[7]; // [sp+Ch] [bp-1Ch] BYREF

  sa_family = a1->sa_family;
  if ( sa_family == 2 || sa_family == 10 )
  {
    v7 = socket(sa_family, 1, 0);
    v5 = v7;
    if ( v7 < 0 )
    {
      v5 = -1;
      perror("socket");
    }
    else
    {
      fcntl(v7, 2, 1);
      v8 = a1->sa_family;
      optval[0] = 1;
      if ( v8 == 10 && setsockopt(v5, 41, 26, optval, 4u) < 0 )
      {
        v5 = -1;
        perror("setsockopt IPV6_V6ONLY");
      }
      else if ( setsockopt(v5, 1, 2, optval, 4u) < 0 )
      {
        v5 = -1;
        perror("setsockopt SO_REUSEADDR");
      }
      else
      {
        v9 = a1->sa_family;
        if ( v9 == 2 )
        {
          v10 = 16;
        }
        else if ( v9 == 10 )
        {
          v10 = 28;
        }
        else
        {
          v10 = 0;
        }
        if ( bind(v5, a1, v10) < 0 )
        {
          v5 = -1;
          perror("bind");
        }
        else if ( listen(v5, 1024) < 0 )
        {
          v5 = -1;
          perror("listen");
        }
      }
    }
  }
  else
  {
    v3 = fopen("/dev/console", "w");
    v4 = v3;
    if ( v3 )
    {
      fprintf(v3, "unknown sockaddr family on listen socket - %d\n", a1->sa_family);
      fclose(v4);
    }
    return -1;
  }
  return v5;
}
```

调试后发现分配的`dword_A9984` 变量的值确实不一样，但后来感觉可能不是变量值不同的问题，因为我发现两种情况调用时给函数`sub_1E6E8()`传入的参数是一样的。我觉得不是`dword_A9984`变量值的问题，莫非与后面`__fds_bits`有关？

![](images/Pasted%20image%2020230523204709.png)

最初我不知道这个东西是干嘛的，就去找资料，发现它原来是一种I/O多路复用技术。当用到`select`时，就会用到`fd_set`结构体 ,里面包含一个`fds_bits` long型数组，里面的每一位代表一个文件描述符。

```c
typedef long int __fd_mask;  //在sys/select.h中
#define __FD_SETSIZE        1024  //在typesizes.h中
#define __NFDBITS   (8 * (int) sizeof (__fd_mask))  //sys/select.h中

typedef struct
{
    __fd_mask fds_bits[__FD_SETSIZE / __NFDBITS];
    #define __FDS_BITS(set) ((set)->fds_bits)
}fd_set;
```

正常情况下如使用`accept`就会发生阻塞，而如果使用`select`它可以继续向下运行，后续通过fd_set判断是否有新消息。对于fd_set涉及四种方法：

```
void FD_CLR(int fd, fd_set *set);  从set集合中把fd清除，将第fd位置0
int FD_ISSET(int fd, fd_set *set);  判断set中fd是否响应，测试set的第fd位是否为1
void FD_SET(int fd, fd_set *set);  把fd添加到set集合中，将set的第fd位置1
void FD_ZERO(fd_set *set);  把集合set清空，将set的所有位置0
```

`select`的原型方法：

```
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
```

简单来说，最初创建一个fd_set变量，然后使用`FD_CLR()` 清空，将想要监听的套接字描述符利用`FD_SET()`方法加进去，然后调用`select()`方法并把fd_set变量作为参数传进去，之后`select()`会修改fd_set变量，若要观察的套接字有消息则对应位置会置1，否则置0，所以就可以通过`FD_ISSET()`遍历所有位来判断是否有新消息。详细过程可以参考文章[网络编程：select多路复用监听accept和write函数解除阻塞_select](https://blog.csdn.net/qq_42343682/article/details/115354021)。

知道了`__fds_bits` 的作用后，就感觉可能也不是这里的问题了。于是我又猜测是使用了`desockmulti.so`进行hook后，会不会本该从某个口如lan或wan口传来的，变成了另一个口，总之因为对`socket`等函数的hook，错误的识别了数据的来源。

为了验证这一想法，首先我去看了一下`desockmulti`的源码[desockmulti.c](https://github.com/zyingp/desockmulti/blob/master/desockmulti.c)，发现它是在创建socket的时候，
将地址族由`AF_INET`(2)与`AF_INET6`(10)将变成了`AF_UNIX`(1)，其中`AF_UNIX` 用于同一台机器上的进程间通信。

```c
int socket(int domain, int type, int protocol)
{
	int fd;
	...
	if ((fd = original_socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		...
	}
	...
	return fd;
	
}
```

那么程序是怎么识别数据是从哪个口传来的呢？又是怎么判断传来的是IPv4还是IPv6的数据呢？

然后我去研究了一下传入上面的函数`sub_1E6E8()`的参数的由来，因为这些参数代表了地址。发现它们全部与函数`sub_1E21C()` 有关。

![](images/Pasted%20image%2020230523213202.png)

进入该函数`sub_1E21C`查看,看到里面包含`http_wanport`, `getaddrinfo`等字符串，猜测它应该是用来获取端口地址的。通过最后两个参数的设置，获取不同的端口地址。

首先看第一次调用，第168行：`sub_1E21C(v55, 0x80u, v61, v54, 0x80u, (int)&v60, 0, -1);`
它的工作流大致如下，首先通过`server_port`调用`getaddrinfo`获取地址，然后while对获取的地址链遍历，若是IPv4(AF_INET=2)则保存在`v14`中，若是IPv6(AF_INET6=10)类型则保存在`v16`中，后续再分别赋值给第1个和第四个参数。

```c
req.ai_family = 0;                            // AF_UNSPEC
req.ai_socktype = 1;                          // SOCK_STREAM
memset(&req.ai_protocol, 0, 20);
req.ai_flags = 1;
if ( !a7 )  //0
  {
    if ( a8 == -1 )  //-1
      snprintf(s, 0xAu, "%d", server_port);
    ...
    goto LABEL_9;
}
...
LABEL_9:
v14 = getaddrinfo((const char *)dword_A9980, s, &req, &pai);
...
v15 = pai;
...
v16 = 0;
  do
{
	while ( 1 )
	{
	  ai_family = v15->ai_family;
	  if ( ai_family != 2 )
		break;
	  if ( !v14 )
		v14 = (int)v15;
	  v15 = v15->ai_next;
	  if ( !v15 )
		goto LABEL_21;
	}
	if ( ai_family == 10 && !v16 )
	  v16 = v15;
	v15 = v15->ai_next;
}
while ( v15 );
LABEL_21:
if ( v16 )
	{
	if ( v16->ai_addrlen <= n )
	{
	  memset(a4, (int)v15, n);
	  memmove(a4, v16->ai_addr, v16->ai_addrlen);
	  *(_DWORD *)a6 = 1;
	  if ( !v14 )
		goto LABEL_35;
	  goto LABEL_24;
	}
	...
}
...
LABEL_24:
	...
if ( a1 && a3 )
{
	memset(a1, 0, a2);
	memmove(a1, *(const void **)(v14 + 20), *(_DWORD *)(v14 + 16));
	*a3 = 1;
}
LABEL_29:
	freeaddrinfo(pai);
```

然后第二次调用，第169行：`sub_1E21C(0, 0, 0, v53, 0x80u, (int)&v59, 1, -1);`，它的作用应该是获取`http_wanport` 端口，然后获取这个口的地址，通过`memmove`将该地址复制给第4个参数。它的流程大致如下：

```c
req.ai_family = 0;                            // AF_UNSPEC
req.ai_socktype = 1;                          // SOCK_STREAM
memset(&req.ai_protocol, 0, 20);
req.ai_flags = 1;
...
v12 = (const char *)nvram_get((int)"http_wanport");
if ( !v12 )
	v12 = "";
v13 = atoi(v12);
snprintf(s, 0xAu, "%d", v13);
v14 = getaddrinfo((const char *)dword_A9980, s, &req, &pai);
...
v15 = pai;
v16 = 0;
do
{
	while ( 1 )
	{
	  ai_family = v15->ai_family;
	  if ( ai_family != 2 )
		break;
	  if ( !v14 )
		v14 = (int)v15;
	  v15 = v15->ai_next;
	  if ( !v15 )
		goto LABEL_21;
	}
	if ( ai_family == 10 && !v16 )
	  v16 = v15;
	v15 = v15->ai_next;
}
while ( v15 );
LABEL_21:
if ( v16 )
	{
	if ( v16->ai_addrlen <= n )
	{
	  memset(a4, (int)v15, n);
	  memmove(a4, v16->ai_addr, v16->ai_addrlen);
	  *(_DWORD *)a6 = 1;
	  if ( !v14 )
		goto LABEL_35;
	  goto LABEL_24;
	}
	...
}
LABEL_24:
	if ( !a2 )
		goto LABEL_29;
LABEL_29:
	freeaddrinfo(pai);
```

也就是说`v54`, `v53`, `v55`代表了不同口的地址，然后传入`sub_1E6EB()`函数中建立套接字绑定监听。这时候突然想到`desockmulti`把所有socket和bind的地址都固定了，即每次调用`sub_1E6E8()`绑定监听的地址都是一样的，这样应该会冲突。

此外，`sub_1E6E8()`函数里调用了`setsockopt()`函数，然后`desockmulti`里没有实现这个函数，只是返回了一个0。看来，响应码400与200不一致的问题还是与`desockmulti`的实现有关。

```c
int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
	if (preeny_socket_hooked[sockfd])
	{
		return 0;
	}
	...
}
```

在下面的函数调用时，正常程序运行时，传入的参数本是不同的，但是由于使用了`desockmulti`进行了hook，虽然传入的参数不同，但实际上hook执行的却是一样的，我猜测它会冲突，于是进行了验证。

![](images/Pasted%20image%2020230523222033.png)

由于之前调试的时候发现正常执行流程会跳到下图第一个分支，而hook后if判断时跳到了第二个分支，即`dword_A9988`所在的分支，也即上面第一个调用`sub_1E6E8()`的变量，我猜测谁先调用`sub_1E6E8()`数据就传递给哪个分支，于是我调试的时候将上图178的调用跳过，发现下图果然跳到了第3个分支（包含`dword_A998C`），即上图第182行调试中首次调用`sub_1e6e8()`的位置。后来将178行和第182行的都跳过函数调用，结果下图果然跳到了第一个分支（包含`dword_A9984`，调试时第一次调用`sub_1E6E8()`的变量），由于第一个分支没有设置`http_from`的值，因此不会出现最开始的不一致的问题，成功返回200。

![](images/Pasted%20image%2020230523222233.png)

然而，后来不一致的根本原因也不是这里的问题（但却是是`http_from`的问题），而是后面这个函数`sub_1EB1C()`里面的问题。它第二个参数传进了`&addr.sa_family` ，而这个值是前面`v19 = accept(dword_A9988, &addr, &addr_len);` 获取得到的，即客户端的地址结构。
![](images/Pasted%20image%2020230519211228.png)

进入到函数中后，v3即代表`sa_family` 的值，因为经过了hook，所以它的`sa_family`的值为`AFF_UNIX`即为1，而非正常的`AF_NET` (2)和`AF_NET6`(10)。这个程序只能识别`AF_NET`和`AF_NET6` ，无法识别hook后的`AF_UNIX`，所以后面会跳到错误的分支去。如下面代码，两个if判断不等于2和10就会跳到错误分支，而不会正常处理，从而导致后续出错。于是后来将22行给v3赋值处进行了patch，将2直接赋值给v3，就解决了这个问题。

![](images/Pasted%20image%2020230519211711.png)

![](images/Pasted%20image%2020230523224222.png)

总结，问题是因为patch后将套接字类型将`sa_family`的值给改变了，改成了`AF_UNIX` (1)，程序在对这个值进行判断时没有相应的解析就会出错。此外还发现`desockmulti.so`实现时没有实现`setsockopt()` 函数，而是直接返回0，这个也可能导致会程序不一致现象发生。说明要想直接使用`desockmulti` 对固件httpd进行模糊测试还是有一定问题的。

## 用AFL++进行模糊测试

在上面所有工作做完后运行下面命令，终于，fuzz起来了！！
```
QEMU_LD_PREFIX=.. QEMU_SET_ENV=USE_RAW_FORMAT=1,LD_PRELOAD=../desockmulti.so ~/Desktop/AFLplusplus/afl-fuzz -Q -i ../../input -o ../../output -- ../usr/sbin/httpd_patched2 -p 8081
```

![](images/Pasted%20image%2020230519220907.png)



## 参考链接
[Fuzzing IoT binaries with AFL++ - Part I (attify.com)](https://blog.attify.com/fuzzing-iot-devices-part-1/)

[Fuzzing IoT binaries with AFL++ - Part II (attify.com)](https://blog.attify.com/fuzzing-iot-binaries-with-afl-part-ii/)

[网络编程：select多路复用监听accept和write函数解除阻塞_select](https://blog.csdn.net/qq_42343682/article/details/115354021)

[desockmulti/desockmulti.c at master · zyingp/desockmulti · GitHub](https://github.com/zyingp/desockmulti/blob/master/desockmulti.c)
