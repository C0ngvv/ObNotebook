## 1.固件选择
对论文里提到的14个固件对Greenhouse进行测试，分别是：

- [TEW-652BRP_v2.0R(2.00).zip](https://downloads.trendnet.com/TEW-652BRP_v2/firmware/TEW-652BRP_v2.0R(2.00).zip)
- [AC1450_V1.0.0.6_1.0.3](https://www.downloads.netgear.com/files/GDC/AC1450/AC1450-V1.0.0.6_1.0.3.zip)
- [FW_RT_AC750_30043808497](https://dlsvr04.asus.com.cn/pub/ASUS/wireless/RT-AC750/FW_RT_AC750_30043808497.zip?model=RT-AC750)
- [TEW-632BRPA1_FW1.10B31](http://downloads.trendnet.com/TEW-632BRP_A1.1/firmware/TEW-632BRPA1(FW1.10B31).zip)
- [DAP-2330_REVA_1.01RC014](https://support.dlink.com/resource/products/dap-2330/REVA/DAP-2330_REVA_FIRMWARE_1.01RC014.ZIP)
- [WNDRMACv2_Version_1.0.0.4](https://www.downloads.netgear.com/files/WNDRMACv2/WNDRMACv2%20Firmware%20Version%201.0.0.4.zip)
- [DAP_1513_REVA_1.01](http://legacyfiles.us.dlink.com/DAP-1513/REVA/FIRMWARE/DAP-1513_REVA_FIRMWARE_1.01.ZIP)
- [FW_RT_G32_C1_5002b](https://dlcdnets.asus.com/pub/ASUS/wireless/RT-G32_C1/FW_RT_G32_C1_5002b.zip?model=RT-G32%20(VER.C1))
- [DAP-2695_REVA_1.11.RC044](https://support.dlink.com/resource/products/dap-2695/REVA/DAP-2695_REVA_FIRMWARE_1.11.RC044.ZIP)
- [WN2000RPT_V1.0.1.20](https://www.downloads.netgear.com/files/GDC/WN2000RPT/WN2000RPT-V1.0.1.20.zip)
- [DIR-601_REVA_1.02](http://legacyfiles.us.dlink.com/DIR-601/REVA/FIRMWARE/DIR-601_REVA_FIRMWARE_1.02.ZIP)
- 


```
sudo docker run -it -p 50003:22 --privileged=true -v ~/Desktop/ghShareSpace:/ghShareSpace greenhouse:usenix-eval-jul2023 /bin/bash

service ssh start
```

之前测试了几个（）都不行，后来试了RT_AC51U_3.0.0.4_380_8497_g179ec32这个可以，但可以显示web登录路由器初始设置页面，点击Apply后没反应，没有达到模糊测试的标准。

![](Greenhouse测试/images/Pasted%20image%2020230814205757.png)

![](Greenhouse测试/images/Pasted%20image%2020230814205915.png)