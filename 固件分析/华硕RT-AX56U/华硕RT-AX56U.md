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

## 报错分析



## 固件启动分析
本来想从内核中查看起始脚本，但是`ubireader` 提取的内容中没有内核相关信息，只有文件系统。

查看文件系统，发现里面存在`etc/init.d/*` 内容，因此先研究一下正常linux启动过程。



