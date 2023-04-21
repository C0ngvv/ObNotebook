
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