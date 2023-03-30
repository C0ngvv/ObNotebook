## 主要内容
- 使用AFL++ Qemu模式模糊测试闭源应用
- 启动Qemu模式持久模式
- 使用QASAN

## 流程
1. 创建PDF种子
2. 启动持久模式
3. 使用QEMU模式对Adobe Reader进行模糊测试，直到发现崩溃
4. 触发崩溃找到漏洞PoC

## 实验
### 1.AFL++ QEMU环境配置
启动AFL++容器，进入容器
```
sudo docker start fe
sudo docker exec -it fe /bin/bash
```

实验需要用到afl-qemu，可使用命令检查是否安装
```
afl-qemu-trace --help
```

如果没有安装的话，安装流程如下
```
sudo apt install ninja-build libc6-dev-i386
cd ~/AFLplusplus/qemu_mode/
CPU_TARGET=i386 ./build_qemu_support.sh
make distrib
sudo make install
```

### 2.Adobe Reader安装
安装依赖，下载`AdbeRdr9.5.1-1_i386linux_enu.deb` ，安装
```
cd /home/fuzzing101/fuzzing_qemu
apt-get install libxml2:i386
wget ftp://ftp.adobe.com/pub/adobe/reader/unix/9.x/9.5.1/enu/AdbeRdr9.5.1-1_i386linux_enu.deb
dpkg -i AdbeRdr9.5.1-1_i386linux_enu.deb

```

! amd64上安装i386程序方法
```
dpkg --add-architecture i386
apt-get update
apt --fix-broken install
apt-get install libxml2:i386
```

程序位于`/opt/Adobe/Reader9/Reader/intellinux/bin/acroread` 

