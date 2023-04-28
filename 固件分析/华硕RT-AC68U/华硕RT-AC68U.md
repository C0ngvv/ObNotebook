
## 复现
### 文件系统提取
binwalk分析
![](images/Pasted%20image%2020230419122456.png)

使用`-Me` 提取固件文件系统
![](images/Pasted%20image%2020230419122751.png)

### 编译main_hook.so
交叉编译链工具，下载使用：[RMerl/am-toolchains: Asuswrt-Merlin toolchains (github.com)](https://github.com/RMerl/am-toolchains)
```
export LD_LIBRARY_PATH="/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/lib"
/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/bin/arm-uclibc-gcc
```

main_hook.c代码
```c
// RTLD_NEXT is a GNU Extension
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

/* Trampoline for the real main() */
static int (*main_orig)(int, char **, char **);

/* Our fake main() that gets called by __libc_start_main() */
int main_hook(int argc, char **argv, char **envp)
{
    // Override origin conn_fp
    FILE **fp = 0x07D600;
    if (argc < 2)
    {
        fprintf(stderr, "Please input filename\n");
        return 1;
    }
    *fp = fopen(argv[1], "r+");
    if (*fp == NULL)
    {
        fprintf(stderr, "Can't open file\n");
        return 2;
    }
    // Get handle_request function's address and run
    int (*do_thing_ptr)() = 0xEEB0;
    int ret_val = (*do_thing_ptr)();
    printf("Ret val %d\n", ret_val);
    return 0;
}

/*
 * Wrapper for __libc_start_main() that replaces the real main
 * function with our hooked version.
 */
int __uClibc_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{
    /* Save the real main function address */
    main_orig = main;

    /* Find the real __libc_start_main()... */
    typeof(&__uClibc_main) orig = dlsym(RTLD_NEXT, "__uClibc_main");

    /* ... and call it with our custom main function */
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
```

编译
```
/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/bin/arm-uclibc-gcc main_hook.c -o main_hook.so -fPIC -shared -ldl
```

### libnvram配置

根据[firmadyne/libnvram: NVRAM emulator (github.com)](https://github.com/firmadyne/libnvram) 中Usage的描述，将`libnvram.so`放到`/firmadyne/libnvram.so`，创建目录
```
mkdir -p /firmadyne/libnvram/
mkdir -p /firmadyne/libnvram.override/
```

挂载
```bash
sudo mount -t tmpfs -o size=10M tmpfs /firmadyne/libnvram
```

查看系统分区 `df -hT` 

![](images/Pasted%20image%2020230421193040.png)

添加新的nvram_get_buf值
```
python3 -c 'open("/firmadyne/libnvram/HTTPD_DBG", "w").write("0")'
```

创建./test.txt文件，里面是网络数据包数据
```
GET /demo HTTP/1.1
Upgrade: WebSocket
Connection: Upgrade
Host: example.com
Origin: http://example.com
WebSocket-Protocol: sample
```

模拟运行
```
qemu-arm -L ./squashfs-root -E LD_PRELOAD=./libnvram.so:./main_hook.so ./squashfs-root/usr/sbin/httpd ./test.txt
```

![](images/Pasted%20image%2020230424202014.png)

## 输入数据
使用下面代码对[nodejs/http-parser: http request/response parser for c (github.com)](https://github.com/nodejs/http-parser)中的test.c文件处理生成corpus
```python
from re import compile

with open('./http-parser/test.c', 'r') as f:
    text = f.read()

start_re = compile('raw= "(.+)"')
middle_re = compile('"(.+)"')
end_re = compile('should_keep_alive')
temp_lst = []
begin_record = False
count = 0

for line in text.split('\n'):
    if matched := start_re.findall(line):
        temp_lst += matched
        begin_record = True
    elif matched := middle_re.findall(line):
        if begin_record:
            temp_lst += matched
    elif end_re.findall(line) and len(temp_lst):
        content = ''.join(temp_lst).replace('\\r\\n', '\r\n')
        with open(f'corpus/http_{count}.txt', 'w') as f:
            f.write(content)
        count += 1
        temp_lst.clear()
        begin_record = False

```

## 模糊测试
安装AFL++，然后运行模糊测试
```bash
export "QEMU_SET_ENV=LD_PRELOAD=./libnvram.so:./main_hook.so" 
export "QEMU_LD_PREFIX=./squashfs-root" 
export "AFL_INST_LIBS=1" 
export "AFL_NO_FORKSRV=1"
../AFLplusplus/afl-fuzz -Q -m none -i corpus/ -o output/ ./squashfs-root/usr/sbin/httpd @@
```

![](images/Pasted%20image%2020230424220808.png) 



## 调试

```
qemu-arm -g 1234 -L ./squashfs-root -E LD_PRELOAD=./libnvram.so:./main_hook.so ./squashfs-root/usr/sbin/httpd ./output/default/crashes/id\:000000\,sig\:11\,src\:000071\,time\:38730\,execs\:1143\,op\:havoc\,rep\:4
```

gdb
```
gdb-multiarch ./squashfs-root/usr/sbin/httpd
target remote :1234
```

### 总结
没有从刚开始就模拟起httpd程序，而是里面的一个处理函数。并且将网络数据流转化为文件流，一切通过Hook代码来实现。利用http-phaser的test.c生成语料库，从而利用AFL++ 的Qemu模式来进行模糊测试。

### 迷途
运行出错

```
ubuntu@ubuntu:~/Desktop/FW_RT_AC68U_300438640558$ qemu-arm -L ./squashfs-root -E LD_PRELOAD=./squashfs-root/firmadyne/libnvram.so ./squashfs-root/usr/sbin/httpd
nvram_get_buf: time_zone_x
sem_lock: Already initialized!
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_buf: Unable to open key: /firmadyne/libnvram/time_zone_x!
nvram_unset: le_restart_httpd
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_int: HTTPD_DBG
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_int: Unable to open key: /firmadyne/libnvram/HTTPD_DBG!
nvram_unset: login_timestamp
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_unset: login_ip
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_unset: login_ip_str
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_buf: https_crt_gen
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_buf: Unable to open key: /firmadyne/libnvram/https_crt_gen!
nvram_get_buf: https_crt_save
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_buf: Unable to open key: /firmadyne/libnvram/https_crt_save!
nvram_set: https_crt_gen = "0"
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_int: debug_logeval
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_int: Unable to open key: /firmadyne/libnvram/debug_logeval!

Broadcast message from systemd-journald@ubuntu (Fri 2023-04-21 19:33:32 CST):

httpd[4372]: Generating SSL certificate...80

1024:error:02001002:lib(2):func(1):reason(2):NA:0:fopen('/etc/cert.pem','r')
1024:error:20074002:lib(32):func(116):reason(2):NA:0:
1024:error:140DC002:lib(20):func(220):reason(2):NA:0:
nvram_set: https_crt_gen = "0"
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_buf: https_crt_save
sem_get: Key: 4101005b

Broadcast message from systemd-journald@ubuntu (Fri 2023-04-21 19:33:32 CST):

httpd[4372]: Failed to initialize SSL, generating new key/cert...80

sem_get: Key: 4101005b
nvram_get_buf: Unable to open key: /firmadyne/libnvram/https_crt_save!
nvram_set: https_crt_gen = "0"
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_int: debug_logeval
sem_get: Key: 4101005b
sem_get: Key: 4101005b
nvram_get_int: Unable to open key: /firmadyne/libnvram/debug_logeval!

Broadcast message from systemd-journald@ubuntu (Fri 2023-04-21 19:33:32 CST):

httpd[4372]: Generating SSL certificate...80

1024:error:02001002:lib(2):func(1):reason(2):NA:0:fopen('/etc/cert.pem','r')
1024:error:20074002:lib(32):func(116):reason(2):NA:0:
1024:error:140DC002:lib(20):func(220):reason(2):NA:0:
nvram_set: https_crt_gen = "0"
sem_get: Key: 4101005b

Broadcast message from systemd-journald@ubuntu (Fri 2023-04-21 19:33:32 CST):

httpd[4372]: Failed to initialize SSL, generating new key/cert...80

sem_get: Key: 4101005b

Broadcast message from systemd-journald@ubuntu (Fri 2023-04-21 19:33:32 CST):

httpd[4372]: Unable to start in SSL mode, exiting! 80
```

`usr/sbin/gencert.sh` 文件内容
```bash
#!/bin/sh
SECS=1262278080

cd /etc

NVCN=`nvram get https_crt_cn`
if [ "$NVCN" == "" ]; then
        NVCN="router.asus.com"
fi

cp -L openssl.cnf openssl.config

I=0
for CN in $NVCN; do
        echo "$I.commonName=CN" >> openssl.config
        echo "$I.commonName_value=$CN" >> openssl.config
        I=$(($I + 1))
done

# create the key and certificate request
#openssl req -new -out /tmp/cert.csr -config openssl.config -keyout /tmp/privkey.pem -newkey rsa:1024 -passout pass:password
# remove the passphrase from the key
#openssl rsa -in /tmp/privkey.pem -out key.pem -passin pass:password
# convert the certificate request into a signed certificate
#openssl x509 -in /tmp/cert.csr -out cert.pem -req -signkey key.pem -setstartsecs $SECS -days 3653 -set_serial $1

# create the key and certificate request
OPENSSL_CONF=/etc/openssl.config openssl req -new -out /tmp/cert.csr -keyout /tmp/privkey.pem -newkey rsa:2048 -passout pass:password
# remove the passphrase from the key
#OPENSSL_CONF=/etc/openssl.cnf openssl rsa -in /tmp/privkey.pem -out key.pem -passin pass:password
# convert the certificate request into a signed certificate
#OPENSSL_CONF=/etc/openssl.cnf RANDFILE=/dev/urandom openssl x509 -in /tmp/cert.csr -out cert.pem -req -signkey key.pem -days 3653 -sha256

# 2020/01/03 import the self-certificate
OPENSSL_CONF=/etc/openssl.config openssl rsa -in /tmp/privkey.pem -out key.pem -passin pass:password
OPENSSL_CONF=/etc/openssl.config RANDFILE=/dev/urandom openssl req -x509 -new -nodes -in /tmp/cert.csr -key key.pem -days 3653 -sha256 -out cert.pem

#       openssl x509 -in /etc/cert.pem -text -noout

# server.pem for WebDav SSL
cat key.pem cert.pem > server.pem

# 2020/01/03 import the self-certificate
cp cert.pem cert.crt

rm -f /tmp/cert.csr /tmp/privkey.pem openssl.config
```


### 钩取main方法
github上给出了Hook main的方法：[Hook main() using LD_PRELOAD (github.com)](https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1)

钩取`__libc_start_main`函数，然后获取真实的`__libc_start_main`函数地址，编写`main_hook` 函数执行我们的代码，其中要调用原始的`main`方法。然后在钩取的`__libc_start_main` 中调用原始的`__libc_start_main`方法，传递参数将`main`函数换为`main_hook`地址。即原始`__libc_start_main->main` 变为`__libc_start_main-> main_hook-> main`。

### qemu-arm与qemu-arm-static
qemu-arm-static是静态编译的，不需要库就能运行。qemu-arm运行还得需要库环境。

![](images/Pasted%20image%2020230421180422.png)

static library(.a)静态库是被直接链接进linker生成最终的可执行文件中，在运行时不需要有库。
shared library(.so)动态库是被链接但没有嵌入最终的可执行文件中，在运行时需要存在库环境。

relocatable file可重定位文件保存包含代码和数据的节。这些文件适合与其他目标文件链接以创建可执行文件、共享目标文件或其他可重定位对象。

executable file可执行文件保存着准备执行的程序。该文件指定exec如何创建程序的进程映像。

shared object file一个共享的对象文件保存着适合在两个上下文中链接的代码和数据。首先，链接编辑器可以将此文件与其他可重定位和共享的目标文件一起处理，以创建其他目标文件。其次，运行时链接器将该文件与一个动态可执行文件和其他共享对象组合在一起，以创建一个进程映像。

### 运行arm busybox
1. 准备工作:
```
sudo apt install qemu-user-static -y
```

2. 编译buildroot， 或单独编译 busybox 等。

3. 找到buidlroot的target目录, 复制qemu-user-static到target目录
```
cp /usr/bin/qemu-arm-static /buildroot-2018.08.2/output/target/usr/bin/
```
4. chroot:
```
sudo chroot /buildroot-2018.08.2/output/target/ /bin/sh
```

好了， 现在你可以为所欲为， 就像在嵌入式系统一样，执行任何busybox 命令了

### AFL++安装

```
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 12 and install the distro default if that fails
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install
```

> Note that `make distrib` also builds FRIDA mode, QEMU mode, unicorn_mode, and more. If you just want plain AFL++, then do `make all`.

安装Qemu模式
```
cd qemu_mode
CPU_TARGET=arm ./build_qemu_support.sh
```

![](images/Pasted%20image%2020230422004523.png)