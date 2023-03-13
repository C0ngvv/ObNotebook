URL:[Fuzzing101/Exercise 4 LibTIFF](https://github.com/antonio-morales/Fuzzing101/tree/main/Exercise%204)

## 环境配置
下载tiff-4.0.4
```
cd /home/fuzzing101
mkdir fuzzing_tiff && cd fuzzing_tiff/

wget https://download.osgeo.org/libtiff/tiff-4.0.4.tar.gz
tar -xzf tiff-4.0.4.tar.gz
```
进入tiff-4.0.4，构建程序
```
cd tiff-4.0.4/
./configure --prefix="/home/fuzzing101/fuzzing_tiff/install/" --disable-shared
make
make install
```
测试tiffinfo文件
```
./install/bin/tiffinfo -D -j -c -r -s -w ./tiff-4.0.4/test/images/palette-1c-1b.tiff
```
![](images/Pasted%20image%2020230313211119.png)
使用了`-j -c -r -s -w` 所有这些标志，来增加代码覆盖率从而增加发现bug的机会。

## 代码覆盖率
代码覆盖率是一个软件指标，显示每行代码被触发的次数。通过使用代码覆盖率，我们将了解模糊器到达了代码的哪些部分，并可视化模糊处理过程。
首先，我们需要安装 lcov。
```
sudo apt install lcov
```
使用标志（编译器和链接器）`--coverage` 重新构建libTIFF：
```
rm -rf /home/fuzzing101/fuzzing_tiff/install
cd /home/fuzzing101/fuzzing_tiff/tiff-4.0.4/
make clean

CFLAGS="--coverage" LDFLAGS="--coverage" ./configure --prefix="/home/fuzzing101/fuzzing_tiff/install/" --disable-shared
make
make install
```
然后通过下面命令收集代码覆盖率
```
cd /home/fuzzing101/fuzzing_tiff/tiff-4.0.4/
lcov --zerocounters --directory ./
lcov --capture --initial --directory ./ --output-file app.info
/home/fuzzing101/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w /home/fuzzing101/fuzzing_tiff/tiff-4.0.4/test/images/palette-1c-1b.tiff
lcov --no-checksum --directory ./ --capture --output-file app2.info
```