

```
import idc 
import ida_segment

# 获取当前地址
address = idc.ScreenEA()
# 获取段起始地址
seg_start = idc.SegStart(address)
# 查看地址所在段名
seg_name = idc.SegName(address)
# 获取指令
mnemonic = idc.GetMnem(addr)
# 获取操作数
instruction = idc.GetDisasm(addr)
# 获取反汇编
ins = idc.GetDisasm(ref)   # 或idc.generate_disasm_line(ea, flags)

```

```
import idc
import ida_segment

data_address = 0x4d3dc
refs = DataRefsTo(data_address)
for ref in refs:
    seg_type = idc.SegName(ref)
    print("- 0x{:X}".format(ref))
    print(seg_type)
    if seg_type != ".text":
        continue
    mnemonic = idc.GetMnem(ref)
    ins = idc.create_insn(ref)
    print(ins)
```

```
获取函数列表遍历
判断函数交叉引用是否为.text
判断指令是否为LDR，且第一个参数为R0-3
判断是否为函数调用
判断另一个参数是否为字符串
调用函数计数+1

排序所有函数计数，最高为注册函数
遍历所有注册函数调用，提取字符串和函数地址
```

```
import idaapi
import idc

# 输入已知的函数调用点地址
call_addr  = 0x3FF7C
func_addr = 0x15D0C

print(idaapi.get_arg_addrs(call_addr))
cfunc = idaapi.decompile(func_addr)

func_type = idaapi.tinfo_t()
cfunc.get_func_type( func_type )
nargs = func_type.get_nargs()
print(nargs)
print(str( func_type.get_nth_arg(0) ))
```

```
for func in Functions():
    print(dir(func))
    print(hex(func),idc.get_func_name(func))
    break

['__abs__', '__add__', '__and__', '__bool__', '__ceil__', '__class__', '__delattr__', '__dir__', '__divmod__', '__doc__', '__eq__', '__float__', '__floor__', '__floordiv__', '__format__', '__ge__', '__getattribute__', '__getnewargs__', '__gt__', '__hash__', '__index__', '__init__', '__init_subclass__', '__int__', '__invert__', '__le__', '__lshift__', '__lt__', '__mod__', '__mul__', '__ne__', '__neg__', '__new__', '__or__', '__pos__', '__pow__', '__radd__', '__rand__', '__rdivmod__', '__reduce__', '__reduce_ex__', '__repr__', '__rfloordiv__', '__rlshift__', '__rmod__', '__rmul__', '__ror__', '__round__', '__rpow__', '__rrshift__', '__rshift__', '__rsub__', '__rtruediv__', '__rxor__', '__setattr__', '__sizeof__', '__str__', '__sub__', '__subclasshook__', '__truediv__', '__trunc__', '__xor__', 'as_integer_ratio', 'bit_count', 'bit_length', 'conjugate', 'denominator', 'from_bytes', 'imag', 'numerator', 'real', 'to_bytes']
0xd938 .init_proc
```