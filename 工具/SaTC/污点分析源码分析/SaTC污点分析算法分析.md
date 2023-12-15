---
title: SaTC污点分析算法分析
date: 2023/12/15
categories: 
tags:
---

# SaTC污点分析算法分析
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


## 参考链接

