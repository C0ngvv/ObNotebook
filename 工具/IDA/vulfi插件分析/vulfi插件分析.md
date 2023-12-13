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

根据规则，获取所有到规则中函数名被调用位置的交叉引用的字典列表。

基于AI辅助，返回的字典结构如下
```json
{
    "function_name1": [
        (xref_address1, function_name1, function_name1),
        (xref_address2, function_name1, function_name1),
        ...
    ],
    "function_name2": [
        (xref_address1, function_name2, function_name2),
        (xref_address2, function_name2, function_name2),
        ...
    ],
    ...
}
```

其中，`function_name1`、`function_name2`等是给定的函数名，`xref_address1`、`xref_address2`等是交叉引用的地址。每个函数名对应一个包含交叉引用元组的列表。每个交叉引用元组包含三个元素：交叉引用的地址、函数名和函数名（可能包含“wrapped”标志）。

后面对于每个找到的交叉引用，它会遍历每个函数，并检查是否满足规则中的条件。如果满足条件，它会将结果添加到结果列表中。

### get_xref_parameters_hexrays()
遍历decompile()的treeitems，当地址为危险调用点地址且类型为cot_call进行处理，获取当前地址的函数名，若与扫描的函数名一致则返回该函数的参数`.a`。

> `op`类型为cot_call, 可以访问cexpr.x.obj_ea字段来获取需要调用函数的地址，通过.a来获取调用函数时的参数列表（`carglist_t`实例对象）

```python
    # Returns an ordered list of workable object that represent each parameter of the function from decompiled code
    def get_xref_parameters_hexrays(self,function_xref,scanned_function):
        # Decompile function and find the call
        try:
            decompiled_function = ida_hexrays.decompile(function_xref)
        except:
            return None
        if decompiled_function is None:
            # Decompilation failed
            return None
        index = 0
        code = decompiled_function.pseudocode
        for tree_item in decompiled_function.treeitems:
            if tree_item.ea == function_xref and tree_item.op == ida_hexrays.cot_call:
                xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                if not xref_func_name:
                    xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                if xref_func_name == scanned_function.lower():
                    return list(tree_item.to_specific_type.a)
            index += 1
        # Call not found :(
        return None
```

每个参数通过VulFiScanner.Param()进行分析。
```python
params_raw = self.get_xref_parameters(scanned_function_xref,scanned_function_name)
for p in params_raw:
		param.append(VulFiScanner.Param(self,p,scanned_function_xref,scanned_function_name))
```




## 参考文献


