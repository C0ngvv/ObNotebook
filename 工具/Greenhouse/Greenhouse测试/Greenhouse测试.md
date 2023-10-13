## 固件选择
对论文里提到的14个固件对Greenhouse进行测试，分别是：

- [TEW-652BRP_v2.0R(2.00)](https://downloads.trendnet.com/TEW-652BRP_v2/firmware/TEW-652BRP_v2.0R(2.00).zip)
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
- [DIR-825_REVB_2.03](https://drivers.softpedia.com/dyn-postdownload.php/54e62cdaa8af972bb4440f97599c2fbc/6528a440/3e14e/4/1)
- [DIR-825 209EUb09](https://ftp.dlink.de/dir/dir-825/archive/driver_software/DIR-825_fw_revb_209EUb09_03_ALL_multi_20130114.zip)
- [DSP-W215_REVB_v2.23B02](https://support.dlink.com/resource/products/dsp-w215/REVB/DSP-W215_REVB_FIRMWARE_v2.23B02.zip)

## TEW-652BRP_v2.0R(2.00)
```
sudo docker run -it --privileged -v /dev:/host/dev greenhouse:usenix-eval-jul2023 bash
/gh/docker_init.sh
/gh/test.sh

sudo docker cp /home/ubuntu/Desktop/test_firmware 2f4:/test_firmware
/gh/run.sh trendnet /test_firmware/TEW-652BRPv2.0R2.00/TEW652BRPR1_FW200b08_nml.bin
```
结果如图所示，重托管成功。

![](images/Pasted%20image%2020231013104745.png)

结果保存在/gh/results目录下

![](images/Pasted%20image%2020231013105318.png)

将结果拷贝到主机
```
docker cp 2f4:/gh/results/6a6b09de38ff710647f598430ccac22924a1dff3697152bd460021ad1929e884/TEW652BRPR1_FW200b08_nml /home/ubuntu/Desktop/test_result/TEW652BRPR1_FW200b08_nml
```

停止greenhouse环境，进入结果的debug目录，启动docker容器
```
sudo docker stop 2f4
cd /home/ubuntu/Desktop/test_result/TEW652BRPR1_FW200b08_nml/debug
sudo docker-compose build
sudo docker-compose up
```

如果遇到下面的情况，就使用命令把冲突的debug网络删除
![](images/Pasted%20image%2020231013111106.png)

```
sudo docker network ls
sudo docker network rm 8188c950b187
```

![](images/Pasted%20image%2020231013111248.png)

然后就可以成功启动

![](images/Pasted%20image%2020231013111326.png)

在浏览器访问:`172.21.0.2:80`，可以成功访问！尝试输入账号密码登录，也可以进行交互。

![](images/Pasted%20image%2020231013111352.png)

不过当输入正确账号密码`admin:admin`登录时，显示就不知道是否正常了。

![](images/Pasted%20image%2020231013111634.png)

从www目录下找到一个settings.asp尝试访问，可以获得

![](images/Pasted%20image%2020231013111845.png)

关闭并清除容器
```
sudo docker-compose down
```






```
sudo docker run -it -p 50003:22 --privileged=true -v ~/Desktop/ghShareSpace:/ghShareSpace greenhouse:usenix-eval-jul2023 /bin/bash

service ssh start
```

之前测试了几个（）都不行，后来试了RT_AC51U_3.0.0.4_380_8497_g179ec32这个可以，但可以显示web登录路由器初始设置页面，点击Apply后没反应，没有达到模糊测试的标准。

![](Greenhouse测试/images/Pasted%20image%2020230814205757.png)

![](Greenhouse测试/images/Pasted%20image%2020230814205915.png)

## AC1450_V1.0.0.6_1.0.3
```
/gh/docker_init.sh
/gh/test.sh
/gh/run.sh netgear /test_firmware/AC1450-V1.0.0.6_1.0.3/AC1450-V1.0.0.6_1.0.3.chk
```
结果如图所示，重托管成功。


## FW_RT_AC750_30043808497


## TEW-632BRPA1_FW1.10B31


## DAP-2330_REVA_1.01RC014

## WNDRMACv2_Version_1.0.0.4

## DAP_1513_REVA_1.01

## FW_RT_G32_C1_5002b

## DAP-2695_REVA_1.11.RC044

## FW_RT_G32_C1_5002b

## DAP-2695_REVA_1.11.RC044

## WN2000RPT_V1.0.1.20

## DIR-601_REVA_1.02

## DIR-825_REVB_2.03

## DIR-825 209EUb09

## DSP-W215_REVB_v2.23B02

