
文件系统提取
```
cd /firmadyne
python3 sources/extractor/extractor.p
y -b Tenda -sql 127.0.0.1 -np -nk /share/US_AC6V1.0BR_V15.03.05.19_multi_TD01.bin images
```

![](images/Pasted%20image%2020230415111751.png)

识别固件架构
```
./scripts/getArch.sh ./images/2.tar.gz
```

![](images/Pasted%20image%2020230415111852.png)

将文件系统内容加载到数据库中
```
./scripts/tar2db.py -i 2 -f ./images/2.tar.gz
```

创建QEMU磁盘镜像
```
sudo ./scripts/makeImage.sh 2
```

![](images/Pasted%20image%2020230415112200.png)

推断网络配置
```
./scripts/inferNetwork.sh 2
```

网络推断好像失败了
![](images/Pasted%20image%2020230415112227.png)

模拟固件
```
./scratch/2/run.sh
```

仿真失败
![](images/Pasted%20image%2020230415112510.png)

# Netgear R8300
```
cd /firmadyne
python3 sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk /share/R8300-V1.0.2.130_1.0.99.chk images
./scripts/getArch.sh ./images/3.tar.gz
./scripts/tar2db.py -i 3 -f ./images/3.tar.gz
sudo ./scripts/makeImage.sh 3
./scripts/inferNetwork.sh 3
./scratch/3/run.sh
```

网络推断失败
![](images/Pasted%20image%2020230415113240.png)

模拟失败
![](images/Pasted%20image%2020230415113345.png)

## 尝试使用FirmAE模拟

Tenda AC6
```
sudo ./run.sh -r Tenda ~/Desktop/firmadyne/US_AC6V1.0BR_V15.03.05.19_multi_TD01.bin
```

失败
![](images/Pasted%20image%2020230419111605.png)

Netgear R8300
```
sudo ./run.sh -r Netgear ~/Desktop/firmadyne/R8300-V1.0.2.130_1.0.99.chk
```

模拟成功
![](images/Pasted%20image%2020230419104137.png)

但网页内容为空
![](images/Pasted%20image%2020230419104218.png)

![](images/Pasted%20image%2020230419104230.png)