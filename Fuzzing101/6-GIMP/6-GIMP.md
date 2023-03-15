## 目标
- 使用Persistent 模式来提高模糊速度
- 如何对交互/GUI应用模糊

## 环境构建
建立测试目录
```
cd /home/fuzzing101/
mkdir fuzzing_gimp && cd fuzzing_gimp
```

安装依赖
```
sudo apt-get install build-essential libatk1.0-dev libfontconfig1-dev libcairo2-dev libgudev-1.0-0 libdbus-1-dev libdbus-glib-1-dev libexif-dev libxfixes-dev libgtk2.0-dev python2.7-dev libpango1.0-dev libglib2.0-dev zlib1g-dev intltool libbabl-dev
```





## 持久模式
在持久模式中，AFL++在一个单个的forked进程中对一个目标模糊多次，而不是每次模糊执行就fork一个新进程。这是非常有效的，这种方法速度可以快10倍或二十倍而没有任何缺点，所有专业的模糊都使用这个模式。

持久模式要求目标能在一个或多个函数中被调用，并且它的状态可以被彻底重置，从而多个调用可以被执行而没有任何资源泄露，早起的运行也不会对后面的运行产生影响。这个的一个指示是afl-fuzz中的`stability` 值，如果这个值在持久模式中比非持久模式中小，那么模糊目标就保持状态。





`--disable-shared` 选项用来告诉编译器，我们想编译得到静态库而非动态链接库。当然不是一定要编译成为静态库，但是这样做在最后调用库函数时，不需要再去考虑解析的问题了。所以对于库的fuzzing，一般都会添加上`--disable-shared` 选项。
