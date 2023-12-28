---
title: SaTC污点分析算法分析
date: 2023/12/15
categories: 
tags:
---

# SaTC污点分析算法分析
## 前面分析结果分析
经过前面的分析步骤，会得到-alter2的结果。该文件每三行分为一组，每行代表的含义如下
```text
# taint_addr
0x000e3314 0x00062e78  # "list"地址； "list"引用地址
# func_addr
0x00062ea4  
# sinkTarget
0x0007e278 0x0007e0b8  # 到达的sink危险函数如strcpy调用点的地址列表

# taint_addr [0]
0x000e2530 0x000581e8  # "wanLinkType"地址和引用处地址
# func_addr  list # 应该是到达sink所途径的函数调用点
0x000405f4 0x00040908 0x000582c4 0x000408f0
# sinkTarget list
0x00040df8 0x00041698 0x000416fc
```

污点分析基于angr来做。

初始化。建立一个空白状态，设置地址为分析的函数地址，然后设置.bss段数据为带"bss"标识的符号值。

污点设置。通过设置带标记`self._taint_buf`(`"taint_buf"`)的符号值来设置污点。下面这个函数为在一个地址处设置污点，它先通过`_get_sym_val()`获取一个带`taint_buf`标记的符号值，然后通过`state.memory.store`将符号值保存在要污染的地址处。
```python
# CoreTaint:604
    def apply_taint(self, current_path, addr, taint_id, bit_size=None):
        """
        Applies the taint to an address addr

        :param current_path: angr current path
        :param addr: address to taint
        :param taint_id: taint identification
        :param bit_size: number of bites
        :return: tainted variable
        """
        self._save_taint_flag()
        bit_size = bit_size if bit_size else self._taint_buf_size
        t = self._get_sym_val(name=self._taint_buf + '_' + taint_id + '_', bits=bit_size).reversed
        self.get_state(current_path).memory.store(addr, t)
        self._restore_taint_flags()
        self._taint_applied = True
        return t
```

在检测一个变量是否被污染时也是通过检测符号值是否包含`"taint_buf"`标记。
```python
    def is_tainted(self, var, path=None, state=None, unconstrained=False):
	    ...
        # Nothing is tainted
        if self._taint_buf not in str(var):
            return False
        ...
```

## 20231227
- angr是如何运行的
	- 如何初始化
	- 使用的API和功能
- 基于angr的污点分析是如何做的
	- 污点设置
	- 污点传播
	- sink判断

`_check_sink`
```
获取当前path和next_path

判断污点数据是否被束缚（有比较等操作），是则执行去污点操作。

如果还没有设置污点，则apply_taint，将字符串参数位置设置了污点符号值 <BV32 Reverse(taint_buf_r1__0_32)>

_is_sink_and_tainted判断当前基本块是否包含sink调用并使用污点数据：跳转地址是否为sink且地址在当前地址在sinkList中，则获取对应sink的进一步判断处理函数进行判段处理。若满足则报告。



污染所有调用地址和参数..

eventually if we are in a loop guarded by a tainted variable

```

`_flat_explore`
```
检测sat state

# check whether we reached a sink
check_path_fun(current_path, guards_info, current_depth, **kwargs)

获取后继succ_path，进行一些状态(sat,unsat,deadended)判断，并设置属性(.sat)

# collect and prepare the successors to be analyzed
将sat和unsat的后继状态合并到一起，并依次进行后续操作进行分析。

一些污点传播策略
当当前调用的函数不在到sink路径上的调用函数时，不进入函数内部进行分析，只将返回值进行污点设置。



```






## 参考链接

