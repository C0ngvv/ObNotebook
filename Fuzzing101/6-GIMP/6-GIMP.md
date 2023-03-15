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









`--disable-shared` 选项用来告诉编译器，我们想编译得到静态库而非动态链接库。当然不是一定要编译成为静态库，但是这样做在最后调用库函数时，不需要再去考虑解析的问题了。所以对于库的fuzzing，一般都会添加上`--disable-shared` 选项。
