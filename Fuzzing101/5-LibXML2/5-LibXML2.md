## 目标构建
下载所需环境
```
cd /home/fuzzing101
mkdir fuzzing_libxml2 && cd fuzzing_libxml2

wget http://xmlsoft.org/download/libxml2-2.9.4.tar.gz
tar zxf libxml2-2.9.4.tar.gz && cd libxml2-2.9.4/
```

构建libxml2
```
sudo apt-get install python3-dev
CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --prefix="/home/fuzzing101/Fuzzing_libxml2/libxml2-2.9.4/install" --disable-shared --without-debug --without-ftp --without-http --without-legacy --without-python LIBS='-ldl'
make -j$(nproc)
make install
```

测试能否正常使用
```
./install/bin/xmllint --memory ./test/wml.xml
```

![](images/Pasted%20image%2020230314201750.png)

## 模糊测试
首先，我们需要获取一些XML示例，使用这个存储库中提供的SampleInput.xml：
```
cd /home/fuzzing101/fuzzing_libxml2/
mkdir afl_in && cd afl_in
wget https://raw.githubusercontent.com/antonio-morales/Fuzzing101/main/Exercise%205/SampleInput.xml
cd ..
```

建立自定义字典。现在，创建一个XML字典或者使用afl++提供的XML字典：
```
mkdir dictionaries && cd dictionaries
wget https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/dictionaries/xml.dict
cd ..
```
![](images/Pasted%20image%2020230314202559.png)

模糊测试。为了捕捉错误，必须启用该参数。我还使用`-x` 标志设置了字典路径，并使用`-D` 标志启用了确定性突变(仅用于主fuzzer)：`--valid` 
使用以下命令运行fuzzer
```
afl-fuzz -m none -i ./afl_in/ -o afl_out -s 123 -x ./dictionaries/xml.dict -D -M master -- ./libxml2-2.9.4/install/bin/xmllint --memory  --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@
```



使用下面命令运行另一个从实例:
```
afl-fuzz -m none -i ./afl_in -o afl_out -s 234 -S slave1 -- ./libxml2-2.9.4/install/bin/xmllint --memory --noenc --nocdata --dtdattr --loaddtd --valid --xinclude @@
```



漏洞触发
```

```

## Questions
1. What is a master instance? What is a slave instance?
2. 