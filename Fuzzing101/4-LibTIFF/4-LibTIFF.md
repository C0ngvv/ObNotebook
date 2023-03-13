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
`CFLAGS` 用于表示C编译器选项；`LDFLAGS` gcc等编译器会用到的一些优化参数.

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
运行一段时间后的结果
![](images/Pasted%20image%2020230313220324.png)

崩溃保存在`out/default/crashes/` 目录下
![](images/Pasted%20image%2020230313220454.png)
使用保存的崩溃触发程序
```
/home/fuzzing101/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w /home/fuzzing101/fuzzing_tiff/out/default/crashes/id:000000,sig:06,src:000016,time:68088,execs:70933,op:havoc,rep:4
```
![](images/Pasted%20image%2020230313220626.png)

测试崩溃样例代码覆盖率，和之前的方法一样
```
cd /home/fuzzing101/fuzzing_tiff/tiff-4.0.4/
lcov --zerocounters --directory ./
lcov --capture --initial --directory ./ --output-file app.info
/home/fuzzing101/fuzzing_tiff/install/bin/tiffinfo -D -j -c -r -s -w /home/fuzzing101/fuzzing_tiff/out/default/crashes/id:000000,sig:06,src:000016,time:68088,execs:70933,op:havoc,rep:4
lcov --no-checksum --directory ./ --capture --output-file app2.info
genhtml --highlight --legend -output-directory ./html-coverage/ ./app2.info
```

## lcov工具介绍
#gcov #lcov 
### 简介
gcov：GCC内置代码覆盖率工具。

lcov: GCC测试覆盖率的前端图形展示工具。它通过收集多个源文件的行、函数和分支的代码覆盖信息（程序执行之后生成gcda、gcno文件） 并且将收集后的信息生成HTML页面。生成HTML需要使用genhtml命令。

### Gcov工作流程

![](images/Pasted%20image%2020230313222320.png)

1. 在 GCC 编译的时加入特殊的编译选项，生成可执行文件，和 `*.gcno`；
2. 运行（测试）生成的可执行文件，生成了 `*.gcda` 数据文件；
3. 有了 `*.gcno` 和 `*.gcda`，通过源码生成 `gcov` 文件，最后生成代码覆盖率报告。

### lcov的使用
首先，在代码编译和链接的时候，需要加上下面两个编译选项。在链接时需要加上gcov链接参数:
`-fprofile-arcs`, `-ftest-coverage` 

一个简单的例子：在lcov目录（我们的这次测试使用的目录）下存在3个文件，a.cpp a.hpp testa.cpp。

1.使用lcov时需要在项目的根路径编译程序
```
g++ testa.cpp a.cpp -fprofile-arcs -ftest-coverage -lgcov -o test_cover
```
归零所有执行过的产生覆盖率信息的统计文件:
```
lcov -d ./ -z
```
2.初始化并创建基准数据文件
```bash
# -c 捕获，-i初始化，-d应用目录，-o输出文件
lcov -c -i -d ./ -o init.info
```
3.执行编译后的测试文件
```bash
./test_cover
```
4.收集测试文件运行后产生的覆盖率文件
```bash
lcov -c -d ./ -o cover.info
```
5.合并基准数据和执行测试文件后生成的覆盖率数据
```bash
# -a 合并文件
lcov -a init.info -a cover.info -o total.info
```
6.过滤不需要关注的源文件路径和信息
```bash
# --remove 删除统计信息中如下的代码或文件，支持正则
lcov --remove total.info '*/usr/include/*' '*/usr/lib/*' '*/usr/lib64/*' '*/usr/local/include/*' '*/usr/local/lib/*' '*/usr/local/lib64/*' '*/third/*' 'testa.cpp' -o final.info
```
7.通过final.info生成html文件
```bash
# -o 生成的html及相关文件的目录名称，--legend 简单的统计信息说明
# --title 项目名称，--prefix 将要生成的html文件的路径 
genhtml -o cover_report --legend --title "lcov"  --prefix=./ final.info
```
看一下目前目录下都生成了哪些文件：
![](images/Pasted%20image%2020230313224325.png)
a.gcda、a.gcno、testa.gcda、testa.gcno就是运行可执行文件后gcov产生的统计信息文件。
cover_report目录就是生成的html信息目录。

这样，就可以通过firefox或者chrome打开cover_report/index.html来查看我们的代码覆盖率。截图如下：
![](images/Pasted%20image%2020230313224407.png)
左侧的路径可以点开，详细看每个文件哪些行被覆盖到了，没有覆盖到。

参考链接：
[关于代码覆盖lcov的使用 - 简书 (jianshu.com)](https://www.jianshu.com/p/a42bbd9de1b7)
[使用 Gcov 和 LCOV 度量 C/C++ 项目的代码覆盖率 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/402463278)

相关链接：
[Installing GCC - GNU Project](https://gcc.gnu.org/install/index.html)
[Linux Test Project - Coverage » lcov (sourceforge.net)](https://ltp.sourceforge.net/coverage/lcov.php)

## ASAN介绍
#ASAN
Address Sanitizer(ASAN)是clang和gcc支持的功能，用于运行时检查内存访问。开启之后，会在目标代码的关键位置，如mallc(), free()，栈上buffer分配等处添加检查代码，一旦发生内存访问错误，如堆栈溢出、UAF、double free等，就可以SIGABRT中止程序。

由于有些内存访问错误并不一定会造成程序崩溃，如越界读，因此在没有开启ASAN的情况下，许多内存漏洞是无法被AFL发现的。所以，编译目标二进制代码时，开启ASAN，也是推荐的做法。对于使用afl-xxx编译来说，只需要设定环境变量AFL_USE_ASAN=1即可。

不过，由于开启ASAN后fuzzing会消耗更多内存，所以这也是需要考虑的因素之一。对于32位程序，基本上800MB即可；但64位程序大概需要20TB！所以，如果要使用ASAN，建议添加CFLAGS=-m32指定编译目标为32位；否则，很有可能因为64位消耗内存过多，程序崩溃。

如果使用了ASAN，还需要注意为afl-fuzz通过选项-m 指定可使用的内存上限。一般对于启用了ASAN的32位程序，-m 1024即可。

参考链接：
[American Fuzzy Lop使用-Galaxy Lab (pingan.com.cn)](http://galaxylab.pingan.com.cn/afl%e4%bd%bf%e7%94%a8101/)

## Questions
1.afl-fuzz参数`-m` 的用途？
> -m megs       - memory limit for child process (0 MB, 0 = no limit [default])