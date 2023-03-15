项目链接：[Fuzzing101/Exercise 6 at main · antonio-morales/Fuzzing101 (github.com)](https://github.com/antonio-morales/Fuzzing101/tree/main/Exercise%206)

## 目标
- 使用Persistent 模式来提高模糊速度
- 如何对交互/GUI应用模糊

## 环境构建
建立测试目录
```
cd /home/fuzzing101/
mkdir fuzzing_gimp && cd fuzzing_gimp
```

按照原教程的内容安装gegl会失败，对于Ubuntu 20.04以上版本可以直接 apt install libgegl-0.4-0 来安装这个0.4版本的库。
```
apt install libgegl-0.4-0
```

下载解压GIMP 2.8.16
```
cd ..
wget https://mirror.klaus-uwe.me/gimp/pub/gimp/v2.8/gimp-2.8.16.tar.bz2
tar xvf gimp-2.8.16.tar.bz2 && cd gimp-2.8.16/
```

使用afl-clang-lto编译
```
CC=afl-clang-lto CXX=afl-clang-lto++ PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/home/fuzzing101/fuzzing_gimp/gegl-0.2.0/ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --disable-gtktest --disable-glibtest --disable-alsatest --disable-nls --without-libtiff --without-libjpeg --without-bzip2 --without-gs --without-libpng --without-libmng --without-libexif --without-aa --without-libxpm --without-webkit --without-librsvg --without-print --without-poppler --without-cairo-pdf --without-gvfs --without-libcurl --without-wmf --without-libjasper --without-alsa --without-gudev --disable-python --enable-gimp-console --without-mac-twain --without-script-fu --without-gudev --without-dbus --disable-mp --without-linux-input --without-xvfb-run --with-gif-compression=none --without-xmc --with-shm=none --enable-debug  --prefix="/home/fuzzing101/fuzzing_gimp/gimp-2.8.16-second/install"
make -j$(nproc)
make install
```


对`./app/app.c` 进行修改
![](images/Pasted%20image%2020230315100422.png)





## 持久模式
#持久模式

### 介绍
在持久模式中，AFL++在一个单个的forked进程中对一个目标模糊多次，而不是每次模糊执行就fork一个新进程。这是非常有效的，这种方法速度可以快10倍或二十倍而没有任何缺点，所有专业的模糊都使用这个模式。

持久模式要求目标能在一个或多个函数中被调用，并且它的状态可以被彻底重置，从而多个调用可以被执行而没有任何资源泄露，早起的运行也不会对后面的运行产生影响。这个的一个指示是afl-fuzz中的`stability` 值，如果这个值在持久模式中比非持久模式中小，那么模糊目标就保持状态。

### 延迟初始化
AFL++尝试通过只执行一次目标二进制文件来优化性能，在执行之前停止它，然后克隆这个“main”进程以获得一个稳定的目标供应给fuzz.main()。尽管这种方法消除了执行程序的大部分操作系统、链接器和libc级别的成本，但它并不总是有助于执行其他耗时的初始化步骤的二进制文件——例如，在获得模糊数据之前解析一个大的配置文件。

在这种情况下，稍微晚一点初始化forkserver是有益的：大部分初始化工作已经完成，但在二进制尝试读取模糊输入并解析它之前。在某些情况下，这可以提供10倍以上的性能增益。您可以在LLVM模式下以一种相当简单的方式实现延迟初始化。

首先，在代码中找到一个可以进行延迟克隆的合适位置。这需要非常小心，以避免破坏二进制。特别是，如果你选择了以下位置，程序可能会故障:

- 任何重要线程或子进程的创建——因为forkserver不能轻易地克隆它们。
- 通过调用或等效调用`setitimer()` 来初始化计时器。
- 临时文件、网络套接字、偏移敏感的文件描述符和类似的共享状态资源的创建——但前提是它们的状态有意义地影响以后的程序行为。
- 对模糊输入的任何访问，包括读取关于其大小的元数据。

选择好位置后，在适当的位置添加以下代码:
```
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

你不需要#ifdef守卫，但是包含它们可以确保程序在使用afl-clang-fast/ afl-clang-lto/afl-gcc-fast以外的工具编译时保持正常工作。最后，使用afl-clang-fast/afl-clang-lto/afl-gcc-fast重新编译程序(afl-gcc或afl-clang将不会生成延迟初始化二进制文件)就可以了!

### 持久模式
一些库提供了无状态的api，或者在处理不同输入文件之间可以重置其状态。当执行这样的重置时，可以重用一个长期存在的进程来尝试多个测试用例，从而消除了重复调用的需要和相关的操作系统开销。











参考链接：

[AFLplusplus/README.persistent_mode.md at stable · AFLplusplus/AFLplusplus (github.com)](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)




`--disable-shared` 选项用来告诉编译器，我们想编译得到静态库而非动态链接库。当然不是一定要编译成为静态库，但是这样做在最后调用库函数时，不需要再去考虑解析的问题了。所以对于库的fuzzing，一般都会添加上`--disable-shared` 选项。

小结AFL++特性
持久模式，并行化，ASAN，指定字典，

## pkg_config
#PKG_CONFIG_PATH   #pkg_config

[【Linux】PKG_CONFIG_PATH_yepoyou的博客-CSDN博客](https://blog.csdn.net/qq_36182852/article/details/109680418)



## Question
内存泄漏是什么？ memory leak

#内存泄漏 

>内存泄漏（Memory Leak）是指程序中已动态分配的堆内存由于某种原因程序未释放或无法释放，造成系统内存的浪费，导致程序运行速度减慢甚至系统崩溃等严重后果。

什么是deterministic mutation?

