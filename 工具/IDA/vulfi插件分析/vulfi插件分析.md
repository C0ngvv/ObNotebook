---
title: vulfi IDA插件分析
date: 2023/12/13
categories: 
tags:
---
# vulfi IDA插件分析
项目地址：[VulFi](https://github.com/Accenture/VulFi)

主要功能实现是在vulfi.py文件，该文件定义了很多类，最主要的是VulFiScanner类，该类负责分析扫描工作。

### \_\_init__()
主要是初始化，判断位数、大小端，设置规则。
```python
    def __init__(self,custom_rules=None):
        # Init class-wide variables
        self.functions_list = []
        if not custom_rules:
            with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"vulfi_rules.json"),"r") as rules_file:
                self.rules = json.load(rules_file)
        else:
            self.rules = custom_rules
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"vulfi_prototypes.json"),"r") as proto_file:
            self.prototypes = json.load(proto_file)
        # get pointer size
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            self.ptr_size = 8
        elif info.is_32bit():
            self.ptr_size = 4
        else:
            self.ptr_size = 2
        # Get endianness
        self.endian = "big" if idaapi.cvar.inf.is_be() else "little"
        # Check whether Hexrays can be used
        if not ida_hexrays.init_hexrays_plugin():
            self.hexrays = False
            self.strings_list = idautils.Strings()
        else:
            self.hexrays = True
            #self.strings_list = idautils.Strings()
```
### start_scan()
启动扫描，进行扫描功能。首先调用prepare_functions_list()获取函数列表。

prepare_functions_list()方法获取所有函数保存到`self.functions_list`中。
```python
    def prepare_functions_list(self):
        self.functions_list = []
        # Gather all functions in all segments
        for segment in idautils.Segments():
            self.functions_list.extend(list(idautils.Functions(idc.get_segm_start(segment),idc.get_segm_end(segment))))

        # Gather imports
        def imports_callback(ea, name, ordinal):
            self.functions_list.append(ea)
            return True

        # For each import
        number_of_imports = idaapi.get_import_module_qty()
        for i in range(0, number_of_imports):
            idaapi.enum_import_names(i, imports_callback)
```

根据规则，获取所有到规则中函数名字交叉引用的字典列表。




## 参考文献


