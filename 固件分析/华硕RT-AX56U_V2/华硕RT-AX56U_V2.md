## 固件下载
登录设备管理页面，看到设备的固件版本号为：3.0.0.4.386_45375-ge5f218b

![](images/Pasted%20image%2020230427190237.png)

官网上已经没有提供这个版本固件的下载链接了，最老的是`3.0.0.4.386.45898`
![](images/Pasted%20image%2020230427190729.png)

查看这些版本固件的下载链接发现它用的是AX55的固件，它的压缩包根据固件的版本号命名，猜测我们想要的固件依然可以通过链接下载。
```
https://dlsvr04.asus.com.cn/pub/ASUS/wireless/RT-AX55/FW_RT_AX55_300438645898.zip?model=RT-AX55
https://dlsvr04.asus.com.cn/pub/ASUS/wireless/RT-AX55/FW_RT_AX55_300438645934.zip?model=RT-AX55
https://dlsvr04.asus.com.cn/pub/ASUS/wireless/RT-AX55/FW_RT_AX55_300438649559.zip?model=RT-AX55
https://dlsvr04.asus.com.cn/pub/ASUS/wireless/RT-AX55/FW_RT_AX55_300438650224.zip?model=RT-AX55
https://dlsvr04.asus.com.cn/pub/ASUS/wireless/RT-AX55/FW_RT-AX55_300438650460.zip?model=RT-AX55
```

所以尝试把压缩包名字换成我们想要的固件版本号，尝试使用此链接下载，结果404 Not Found。再尝试在网上搜索RT-AX55，得到RT-AX55的支持页面：[RT-AX55｜無線路由器｜ASUS 香港](https://www.asus.com/hk/networking-iot-servers/wifi-routers/all-series/rt-ax55/helpdesk_bios/?model2Name=RT-AX55)，使用它的固件下载链接改成我们想要的固件版本号进行下载就可以下载成功了。
```
原始某版本下载链接
https://dlcdnets.asus.com/pub/ASUS/wireless/RT-AX55/FW_RT_AX55_300438645898.zip?model=RT-AX55
想要版本下载链接
https://dlcdnets.asus.com/pub/ASUS/wireless/RT-AX55/FW_RT_AX55_300438645375.zip?model=RT-AX55
```

下载完后尝试使用binwalk提取，但是什么都没提取到。
![](images/Pasted%20image%2020230427192133.png)

提取出的rootfs_ubifs是空的，用ubireader提取也是一样。
![](images/Pasted%20image%2020230427192255.png)


