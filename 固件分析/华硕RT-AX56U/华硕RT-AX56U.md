## 固件下载
固件下载：[RT-AX56U｜无线路由器｜ASUS 中国](https://www.asus.com.cn/networking-iot-servers/wifi-routers/asus-wifi-routers/rt-ax56u/helpdesk_bios/?model2Name=RT-AX56U)

![](images/Pasted%20image%2020230427114841.png)

## 文件系统提取与简单分析
binwalk分析是ubi
![](images/Pasted%20image%2020230427115203.png)

使用ubireader提取
```
ubireader_extract_files FW_RT_AX56U_300438649380.w
```

![](images/Pasted%20image%2020230427115316.png)

提取出文件系统
![](images/Pasted%20image%2020230427115332.png)

寻找`httpd` 程序，在`usr/sbin/httpd` 
```
find . -name "http*"
```

![](images/Pasted%20image%2020230427115548.png)

查看架构是arm
![](images/Pasted%20image%2020230427115635.png)

尝试模拟，需要先加执行权限，然后尝试使用`qemu-arm-static` 模拟，报错。
```
sudo chroot . ./qemu-arm-static ./usr/sbin/httpd
```

![](images/Pasted%20image%2020230427115818.png)

![](images/Pasted%20image%2020230427115905.png)

`FW_RT_AX56U_300438644266`版本运行与此相同，现在下面研究的是这个版本。

文章
[Asus 路由器栈溢出漏洞分析](https://www.ctfiot.com/31802.html)

现在直接按照之前RT-AC68U那篇文章的思路进行测试。

## 尝试搭建测试环境
编写main_hook.c代码
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
    FILE **fp = 0xA0AB4;
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
    int (*do_thing_ptr)() = 0x19644;
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
```bash
export LD_LIBRARY_PATH="/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/lib"
/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/bin/arm-uclibc-gcc main_hook.c -o main_hook.so -fPIC -shared -ldl
```

将libnvram.so拷到当前目录

创建./test.txt文件，里面是网络数据包数据
```
GET /demo HTTP/1.1
Upgrade: WebSocket
Connection: Upgrade
Host: example.com
Origin: http://example.com
WebSocket-Protocol: sample
```

仿真运行
```bash
qemu-arm -L ./rootfs_ubifs -E LD_PRELOAD=./libnvram.so:./main_hook.so ./rootfs_ubifs/usr/sbin/httpd ./test.txt
```

报错说找不到`libdl.so.0`和`libc.so.0`，用`libdl.so.2`和`libc.so.6`分别拷贝一个。

![](images/Pasted%20image%2020230428114048.png)

再运行就仿真起来了

![](images/Pasted%20image%2020230428114205.png)







