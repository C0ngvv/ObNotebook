首先测试一个固件，然后基于分析结果查看SaTC源码各部分功能。

## Netgear R6400v2测试
固件来自于其提供的测试案例，这里测试其中的Netgear R6400v2的命令注入和缓冲区溢出。
```
python satc.py -d /workspace/NetGear/RV6400_v2/squashfs-root -o /workspace/NetGear/RV6400_v2/output --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof --taint_check
```

![](images/Pasted%20image%2020231016224033.png)

分析结果是这种形式

![](images/Pasted%20image%2020231017085006.png)

我尝试使用IDA跟踪其路径但是发现IDA反编译的程序好像有点问题，后来用ghidra就可以了，下面放一下432a4()函数反编译对比图。

![](images/Pasted%20image%2020231017085221.png)

![](images/Pasted%20image%2020231017085241.png)

## SaTC源码分析
### satc.py
这个文件是所有分析的起点，所以先从这里开始分析。在main()方法里首先解析参数，然后：
1. 调用`front_analysise(args)`进行前端关键字提取并分析获取边界二进制程序列表。
2. 如果ghidra_script是share2sink类型的就调用`ghidra_analysise(args, bin_list)`进行分析，缓冲区溢出和命令注入脚本不在这里分析。
3. 如果启动ghidra_script和taint_check，对于命令注入和缓冲区溢出设置相关的标志，然后调用`taint_stain_analysis(bin_path, ghidra_result, args.output)`进行污点分析。

#### front_analysise()
