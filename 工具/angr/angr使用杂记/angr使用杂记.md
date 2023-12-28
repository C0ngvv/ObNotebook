---
title: angr使用杂记
date: 2023/12/28
categories: 
tags:
---
# angr使用杂记
## IR
相关介绍：[angr中的中间语言表示VEX - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/349182248)

`block.vex.jumpkind`表示当前IR（Intermediate Representation）指令的跳转类型。

- `"Ijk_Boring"`：普通的跳转类型，表示顺序执行下一条指令。
- `"Ijk_Call"`：函数调用类型，表示当前指令是一个函数调用。
- `"Ijk_Ret"`：函数返回类型，表示当前指令是一个函数返回。
- `"Ijk_Sys"`：系统调用类型，表示当前指令是一个系统调用。
- `"Ijk_Conditional"`、`"Ijk_Switch"`

除上述类型外，还有其他一些特殊的跳转类型，例如异常跳转、间接跳转等。

```
ipdb> dir(bl.vex)
['__class__', '__delattr__', '__doc__', '__format__', '__getattribute__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '_addr', '_direct_next', '_from_c', '_get_defaultexit_target', '_is_defaultexit_direct_jump', '_pp_str', '_size', 'addr', 'all_constants', 'arch', 'constant_jump_targets', 'constant_jump_targets_and_jumpkinds', 'constants', 'direct_next', 'expressions', 'from_c', 'from_py', 'instructions', 'jumpkind', 'next', 'offsIP', 'operations', 'pp', 'size', 'statements', 'stmts_used', 'tyenv', 'typecheck']
```

```
ipdb> bl.vex.pp()
IRSB {
   t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I32 t4:Ity_I32 t5:Ity_I32 t6:Ity_I32 t7:Ity_I32 t8:Ity_I32 t9:Ity_I32 t10:Ity_I32 t11:Ity_I32 t12:Ity_I32 t13:Ity_I32 t14:Ity_I32 t15:Ity_I32 t16:Ity_I32 t17:Ity_I32 t18:Ity_I32 t19:Ity_I32 t20:Ity_I32 t21:Ity_I32 t22:Ity_I32

   00 | ------ IMark(0x62e8c, 4, 0) ------
   01 | t19 = GET:I32(fp)
   02 | t18 = Sub32(t19,0x00000014)
   03 | t2 = GET:I32(r0)
   04 | STle(t18) = t2
   05 | PUT(ip) = 0x00062e90
   06 | ------ IMark(0x62e90, 4, 0) ------
   07 | t20 = t18
   08 | t5 = LDle:I32(t20)
   09 | PUT(r0) = t5
   10 | PUT(ip) = 0x00062e94
   11 | ------ IMark(0x62e94, 4, 0) ------
   12 | t8 = LDle:I32(0x000630b0)
   13 | ------ IMark(0x62e98, 4, 0) ------
   14 | t9 = GET:I32(r4)
   15 | t12 = Add32(t9,t8)
   16 | PUT(r3) = t12
   17 | ------ IMark(0x62e9c, 4, 0) ------
   18 | PUT(r1) = t12
   19 | ------ IMark(0x62ea0, 4, 0) ------
   20 | PUT(r2) = 0x0000000a
   21 | ------ IMark(0x62ea4, 4, 0) ------
   22 | PUT(lr) = 0x00062ea8
   NEXT: PUT(pc) = 0x0007dec0; Ijk_Call
}
```



## 参考链接

