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
satc.py文件是所有分析的起点，所以先从这里开始分析。在main()方法里首先解析参数，然后：
1. 调用`front_analysise(args)`进行前端关键字提取并分析获取边界二进制程序列表。
2. 如果有ghidra_script就调用`ghidra_analysise(args, bin_list)`进行分析。
3. 最后调用`taint_stain_analysis(bin_path, ghidra_result, args.output)`对污点分析结果分析

### front_analysise()
首先进行前端分析进行（不同类型的）字符串提取，调用FrontAnalysise().analysise()方法，结果在f_res变量中，后续通过Output().write_file_info()方法写入文件中。

然后进行后端二进制分析识别边界二进制程序，调用BlackAnalysise().analysise()方法，通过get_result()方法可以获得结果。

还有针对UPNP具体分析的以及其他的辅助性分析操作，不做分析，最后返回边界二进制列表border_bin，类型为列表，里面元素为元组(f_name, f_path)。

### ghidra_analysise()
创建ghidra工作目录，依次执行ghidra脚本分析：

```
ref2share: ref2share.py
ref2sink_bof: ref2sink_bof.py
ref2sink_cmdi: ref2sink_cmdi.py
share2sink: share2sink.py
```

### ref2sink_bof.py
依次遍历提取的字符串作为参数，调用searchParam(param)进行危险路径分析。

#### searchParam()
获取程序最小和最大地址，依次寻找匹配字符串target，通过`getReferencesTo()`找到交叉引用字符串的位置，调用`getFunctionContaining()`找到引用它的函数，如0x12B2位置的字符串变量"pptp_localip"被位于函数FUN_00024e74中的0x0002506c和0x0002507c位置引用。

```
start searching "pptp_localip" ...
Reference From 0x0002506c (FUN_00024e74) To 0x000d12b2 ("pptp_localip")
Reference From 0x0002507c (FUN_00024e74) To 0x000d12b2 ("pptp_localip")
```

找到引用后就调用`findSinkPath(ref.fromAddress, curAddr, target)`进行污点分析查询危险路径，并将引用地址加入检查过的引用地址变量`checkedRefAddr`中。

#### findSinkPath()
- 先调用`getFunctionContaining(refaddr)`获取函数调用图
- 然后通过`dfs(startFunc, [], refaddr)`递归寻找是否存在到达sink的路径，并对常量字符串参数和格式字符串参数检查确定是否具有漏洞，没有漏洞的函数加入`safeFuncs`中减少后面搜索量。
- 最后调用`searchStrAArg(startFunc)`通过启发式增加识别的参数，如果函数一直调用同一个字符串参数超过阈值，且该参数不在识别字符串里，就把该字符串加入到识别的字符串中，后续也对其进行分析。

### taint_stain_analysis()
#### conv_Ghidra_output.main(ghidra_analysis_result)
将分析结果简化，提取出字符串和引用地址组成元组作为字典key，将路径地址作为value，以及最后一个点作为sink点，然后向-alter2文件输出三行：
```
字符串地址 引用地址
最后一条从引用地址到sink点前的路径
最后一条的sink点位置
```