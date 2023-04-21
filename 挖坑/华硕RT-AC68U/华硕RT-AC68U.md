
binwalk分析
![](images/Pasted%20image%2020230419122456.png)

使用`-Me` 提取固件文件系统
![](images/Pasted%20image%2020230419122751.png)


```
export LD_LIBRARY_PATH="/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/lib"
/home/ubuntu/Desktop/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3/bin/arm-uclibc-gcc
```

挂载
```bash
sudo mount -t tmpfs -o size=10M tmpfs /fimadyne/libnvram
```

查看系统分区 `df -hT` 

![](images/Pasted%20image%2020230421193040.png)

添加新的nvram_get_buf值
```
python3 -c 'open("/firmadyne/libnvram/HTTPD_DBG", "w").writ
e("0")'
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