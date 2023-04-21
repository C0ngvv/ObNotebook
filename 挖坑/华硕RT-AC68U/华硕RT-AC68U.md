
binwalk分析
![](images/Pasted%20image%2020230419122456.png)

使用`-Me` 提取固件文件系统
![](images/Pasted%20image%2020230419122751.png)


```
export LD_LIBRARY_PATH="/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/lib"
/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/bin/arm-uclibc-gcc
```

跑
```
qemu-arm -L ./squashfs-root -E LD_PRELOAD=./squashfs-root/firmadyne/libnvram.so ./squashfs-root/usr/sbin/httpd
```



### qemu-arm与qemu-arm-static
qemu-arm-static是静态编译的，不需要库就能运行。qemu-arm运行还得需要库环境。

![](images/Pasted%20image%2020230421180422.png)



static library(.a)静态库是被直接链接进linker生成最终的可执行文件中，在运行时不需要有库。
shared library(.so)动态库是被链接但没有嵌入最终的可执行文件中，在运行时需要存在库环境。

relocatable file可重定位文件保存包含代码和数据的节。这些文件适合与其他目标文件链接以创建可执行文件、共享目标文件或其他可重定位对象。

executable file可执行文件保存着准备执行的程序。该文件指定exec如何创建程序的进程映像。

shared object file一个共享的对象文件保存着适合在两个上下文中链接的代码和数据。首先，链接编辑器可以将此文件与其他可重定位和共享的目标文件一起处理，以创建其他目标文件。其次，运行时链接器将该文件与一个动态可执行文件和其他共享对象组合在一起，以创建一个进程映像。