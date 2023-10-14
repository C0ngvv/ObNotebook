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
sudo docker cp 2f4:/gh/results/6a6b09de38ff710647f598430ccac22924a1dff3697152bd460021ad1929e884/TEW652BRPR1_FW200b08_nml /home/ubuntu/Desktop/test_result/TEW652BRPR1_FW200b08_nml
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

## AC1450_V1.0.0.6_1.0.3
```
/gh/docker_init.sh
/gh/test.sh
/gh/run.sh netgear /test_firmware/AC1450-V1.0.0.6_1.0.3/AC1450-V1.0.0.6_1.0.3.chk
```

结果如图所示，重托管成功。

![](images/Pasted%20image%2020231013140334.png)

结果保存在/gh/results目录下

![](images/Pasted%20image%2020231013140433.png)

将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995/AC1450_V1.0.0.6_1.0.3.chk /home/ubuntu/Desktop/test_result/AC1450_V1.0.0.6_1.0.3.chk
```

进入结果的debug目录，启动docker容器
```
cd /home/ubuntu/Desktop/test_result/AC1450_V1.0.0.6_1.0.3.chk/debug
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

## FW_RT_AC750_30043808497
```
/gh/docker_init.sh
/gh/test.sh
/gh/run.sh asus /test_firmware/FW_RT_AC750_30043808497/RT-AC51U_3.0.0.4_380_8497-g179ec32.trx
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013155228.png)


结果保存在/gh/results目录下
![](images/Pasted%20image%2020231013155338.png)


将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/59f03e424c464cbb729d46e9f88da7dad98eb37e607b07cb49660c0517a49717/RT_AC51U_3.0.0.4_380_8497_g179ec32.trx /home/ubuntu/Desktop/test_result/RT_AC51U_3.0.0.4_380_8497_g179ec32.trx
```


## TEW-632BRPA1_FW1.10B31
```
/gh/run.sh trendnet /test_firmware/TEW-632BRPA1FW1.10B31/TEW632BRPA1_FW110B31.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013170010.png)

结果保存在/gh/results目录下
![](images/Pasted%20image%2020231013170043.png)

将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/a28394246ff8925b79f9dbdc85c73b0d9e29d26b81fb1bcab648d6ce1a187dd9/TEW632BRPA1_FW110B31 /home/ubuntu/Desktop/test_result/TEW632BRPA1_FW110B31
```


## DAP-2330_REVA_1.01RC014
```
/gh/run.sh dlink /test_firmware/DAP-2330_REVA_FIRMWARE_1.01RC014/DAP2330-firmware-v101-rc014.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013183044.png)

结果保存在/gh/results目录下
![](images/Pasted%20image%2020231013183128.png)

将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/cbec3a0713a694fbf717520a90ab6e7d61475a4c92a843c5e424157c01a6e362/DAP2330_firmware_v101_rc014 /home/ubuntu/Desktop/test_result/DAP2330_firmware_v101_rc014
```



## WNDRMACv2_Version_1.0.0.4
```
/gh/run.sh netgear /test_firmware/WNDRMACv2V1.0.0.4/WNDRMACv2-V1.0.0.4.img
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013201427.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/935e41a07256af9c4166e8f9bc77d1022e0bbde63f4ad73be46df1d653cba0b2/WNDRMACv2_V1.0.0.4.img /home/ubuntu/Desktop/test_result/WNDRMACv2_V1.0.0.4.img
```

启动后可以访问
![](images/Pasted%20image%2020231014203238.png)

## DAP_1513_REVA_1.01
```
/gh/run.sh dlink /test_firmware/DAP-1513_REVA_FIRMWARE_1.01/DAP-1513FW1.01b05.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013221700.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/978cf40888348a5487f45c44d1feb8bf947326d1cc35ca675f137412d413d373/DAP_1513FW1.01b05 /home/ubuntu/Desktop/test_result/DAP_1513FW1.01b05
```

## FW_RT_G32_C1_5002b
```
/gh/run.sh asus /test_firmware/FW_RT_G32_C1_5002b/RT-G32C1_5.0.0.2b.trx
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013230537.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/8341ac22a8e2de962e33fe3b34f2f7df67a5fff0fc44386baf98f06a1112c450/RT_G32C1_5.0.0.2b.trx /home/ubuntu/Desktop/test_result/RT_G32C1_5.0.0.2b.trx
```



## DAP-2695_REVA_1.11.RC044
```
/gh/run.sh dlink /test_firmware/DAP-2695_REVA_FIRMWARE_1.11.RC044/DAP-2695-firmware-v111-rc044.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231013235743.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/0ab3b8367ab862344a74eaf8a90a69749ceca7d4f4d46353281a7e0001f876f2/DAP_2695_firmware_v111_rc044 /home/ubuntu/Desktop/test_result/DAP_2695_firmware_v111_rc044
```


## WN2000RPT_V1.0.1.20
```
/gh/run.sh netgear /test_firmware/WN2000RPT-V1.0.1.20/WN2000RPT-V1.0.1.20.img
```

结果如图所示，重托管成功。

![](images/Pasted%20image%2020231014090550.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/fea9e1327adedca1baa0cbe4c0244606b9241dc17debac2307b001503d4758a9/WN2000RPT_V1.0.1.20.img /home/ubuntu/Desktop/test_result/WN2000RPT_V1.0.1.20.img
```

可以启动，账号密码：`admin:password`

![](images/Pasted%20image%2020231014204700.png)

## DIR-601_REVA_1.02
```
/gh/run.sh dlink /test_firmware/DIR-601_REVA_FIRMWARE_1.02/dir601_FW_102NA.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231014095544.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/41a11fde62a2e1988fb1606bace0b268a39293e3c0c6fc992478897972e5cd74/dir601_FW_102NA /home/ubuntu/Desktop/test_result/dir601_FW_102NA
```





## DIR-825_REVB_2.03
```
/gh/run.sh dlink /test_firmware/dir825_revB_fw_203NA/dir825_revB_fw_203NA.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231014192329.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/379836b8625f32fb3c2642656f056e9bf43f929101e2ff758bb5049c5373ef2d/dir825_revB_fw_203NA /home/ubuntu/Desktop/test_result/dir825_revB_fw_203NA
```


## DIR-825 209EUb09
```
/gh/run.sh dlink /test_firmware/DIR-825_fw_revb_209EUb09_03_ALL_multi_20130114/DIR825B1_FW209EUB09_03.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231014153533.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/149c878232fa94b3d3063be251c70c366165a153167a66f94140a3067108ce0c/DIR825B1_FW209EUB09_03 /home/ubuntu/Desktop/test_result/DIR825B1_FW209EUB09_03
```




## DSP-W215_REVB_v2.23B02
```
/gh/run.sh dlink /test_firmware/DSP-W215_REVB_FIRMWARE_v2.23B02/DSP-W215B2_FW223B02.bin
```

结果如图所示，重托管成功。
![](images/Pasted%20image%2020231014125846.png)

结果保存在/gh/results目录下，将结果拷贝到主机
```
sudo docker cp 2f4:/gh/results/3adfdded29a23a734cb91fc64602323ff0ae835de7534c07cf3cd0bb637bbfb2/DSP_W215B2_FW223B02 /home/ubuntu/Desktop/test_result/DSP_W215B2_FW223B02
```








```
sudo docker run -it -p 50003:22 --privileged=true -v ~/Desktop/ghShareSpace:/ghShareSpace greenhouse:usenix-eval-jul2023 /bin/bash

service ssh start
```

之前测试了几个（）都不行，后来试了RT_AC51U_3.0.0.4_380_8497_g179ec32这个可以，但可以显示web登录路由器初始设置页面，点击Apply后没反应，没有达到模糊测试的标准。

![](Greenhouse测试/images/Pasted%20image%2020230814205757.png)

![](Greenhouse测试/images/Pasted%20image%2020230814205915.png)
