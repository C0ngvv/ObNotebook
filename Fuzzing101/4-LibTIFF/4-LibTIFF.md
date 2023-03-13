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
-   `lcov --zerocounters --directory ./` : Reset previous counters
-   `lcov --capture --initial --directory ./ --output-file app.info` : Return the "baseline" coverage data file that contains zero coverage for every instrumented line
-   `$HOME/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w $HOME/fuzzing_tiff/tiff-4.0.4/test/images/palette-1c-1b.tiff` : Run the application you want to analyze . You can run it multiple times with different inputs
-   `lcov --no-checksum --directory ./ --capture --output-file app2.info`: Save the current coverage state into the app2.info file
生成html输出
```
genhtml --highlight --legend -output-directory ./html-coverage/ ./app2.info
```
代码覆盖率就保存在对应目录下，然后可以在浏览器中打开index.html文件

![](images/Pasted%20image%2020230313213059.png)

## 模糊测试
现在开启ASAN编译libtiff
```
rm -r /home/fuzzing101/fuzzing_tiff/install
cd /home/fuzzing101/fuzzing_tiff/tiff-4.0.4/
make clean

export LLVM_CONFIG="llvm-config-11"
CC=afl-clang-lto ./configure --prefix="/home/fuzzing101/fuzzing_tiff/install/" --disable-shared
AFL_USE_ASAN=1 make -j4
AFL_USE_ASAN=1 make install
```
模糊测试
```
afl-fuzz -m none -i /home/fuzzing101/fuzzing_tiff/tiff-4.0.4/test/images/ -o /home/fuzzing101/fuzzing_tiff/out/ -s 123 -- /home/fuzzing101/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w @@
```


