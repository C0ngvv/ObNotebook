

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

```