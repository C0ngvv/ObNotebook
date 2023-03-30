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

环境构建出现了一些问题，运行acroread提示缺少`libgdk_pixbuf_xlib-2.0.so.0` 共享库。
```
[afl++ feda81819d2a] /home/fuzzing101/fuzzing_qemu # acroread -help
dirname: missing operand
Try 'dirname --help' for more information.
/opt/Adobe/Reader9/Reader/intellinux/bin/acroread: error while loading shared libraries: libgdk_pixbuf_xlib-2.0.so.0: cannot open shared object file: No such file or directory
```

下面介绍一下使用流程。

### 3.准备种子语料库
下载语料库
```
wget https://corpora.tika.apache.org/base/packaged/pdfs/archive/pdfs_202002/libre_office.zip
unzip libre_office.zip -d extracted
```

仅复制小于2kB的文件来提高模糊速度
```
mkdir -p /home/fuzzing101/fuzzing_qemu/afl_in
find ./extracted -type f -size -2k \
    -exec cp {} /home/fuzzing101/fuzzing_qemu/afl_in \;
```

### 4.  方法1：直接模糊测试
最简单的方式是使用afl-fuzz加上`-Q` 参数。

```
ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' afl-fuzz -Q -i ./afl_in/ -o ./afl_out/ -t 2000 -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript @@
```

因为`/opt/Adobe/Reader9/bin/acroread` 是一个脚本文件，真实的二进制文件在`/opt/Adobe/Reader9/Reader/intellinux/bin/acroread` 。如果尝试直接执行它可能会出现错误：`acroread must be executed from the startup script`，所以设置`ACRO_INSTALL_DIR` 和 `ACRO_CONFIG`变量，设置`LD_LIBRARY_PATH` 指定动态链接库寻找位置。

### 5.方法2：持久模式提高效率
有源码时可以使用`AFL_LOOP` 来启动持久模式，没有源码时使用`AFL_QEMU_PERSISTENT` 指定持久循环起始点，建议设置该点为函数开头。可以使用IDA或Ghidra分析获取这个点地址：`0x085478AC`。

同样设置`AFL_QEMU_PERSISTENT_GPR=1` 变量，可以保存并在每次持续循环中恢复通用寄存器的原始值。

```
AFL_QEMU_PERSISTENT_ADDR=0x085478AC AFL_QEMU_PERSISTENT_GPR=1 ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' afl-fuzz -Q -i ./afl_in/ -o ./afl_out/ -t 2000 -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript @@
```

### 6.触发
使用崩溃文件直接给afl-qemu-trace会直接提示段错误。
```
ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' /usr/local/bin/afl-qemu-trace -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript [crashFilePath] 
```

使用QASan获取更多stacktrace信息，设置`AFL_USE_QASAN=1`来启用。
```
AFL_USE_QASAN=1 ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' /usr/local/bin/afl-qemu-trace -- /opt/Adobe/Reader9/Reader/intellinux/bin/acroread -toPostScript [crashFilePath] 
```