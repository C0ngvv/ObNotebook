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

## AFL的并行模式
### 介绍
每个afl-fuzz副本会占据一个CUP内核，这意味着在n核的系统上可以运行n个并发模糊测试，如果在多个系统上只运行一个模糊作业，会使硬件利用率不足，因此并行化始终是好的方法。

当面向多个不相关的二进制模糊测试或使用工具“non-instrumented"(-n)模式时，启动几个单独的afl-fuzz实例就可以了。而当多个模糊器面向一个共同的目标模糊测试时就复杂了：如果一个模糊器生成了一个难以命中但感兴趣的测试案例时，其余的模糊实例不能使用该案例来指导它们的工作。为了解决这个问题，afl-fuzz提供了一个简单的方法来同步测试用例。

### 单系统并行
如果希望在本地系统的多个核上并行一个任务，只需创建一个新的空输出目录 (“sync_dir”) ，该目录将由afl-fuzz的所有实例共享；然后为每个实例提出一个命名方案——比如“fuzzer01”，“fuzzer02”等等。

运行第一个节点(" main node "， -M)，如下所示:
```
./afl-fuzz -i testcase_dir -o sync_dir -M fuzzer01 [...other stuff...]
```

然后，启动次要(-S)实例:
```
./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer02 [...other stuff...]
./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]
```

每个fuzzer将把它的状态保存在一个单独的子目录中，如:/path/to/sync_dir/fuzzer01/

每个实例还会周期性地重新扫描顶级同步目录，以寻找其他fuzzer发现的任何测试用例——当它们被认为足够有趣时，将它们合并到自己的fuzzing中。出于性能考虑，只有-M主节点与所有人同步队列，-S辅助节点只从主节点同步。

-M和-S模式的区别在于，主实例仍将执行确定性检查；而次要实例将直接进行随机调整。

注意，必须始终有一个-M主实例！运行多个-M实例是浪费！

您还可以使用提供的afl-whatsup工具从命令行监视作业的进度。当实例不再找到新的路径时，可能就该停止了。

### 多个-M mains





参考链接：

[并行模糊测试 |AFLplusplus](https://aflplus.plus/docs/parallel_fuzzing/)



## Questions
1. What is a master instance? What is a slave instance?
2. What is deterministic check? What is random tweak?