修改FIDL的controlFlowinator类和相关的函数和变量类，来允许我们直接获取IDA 反编译界面的关于变量值距离bp和sp的距离。

## 修改
在类外添加我们定义的方法
```python
def getParamDefine(param):
    if param.is_pointer:
        if '__fastcall' in param.type_name:
            tmp = param.type_name.split('__fastcall *')
            define_str = "{}__fastcall *{}{};".format(tmp[0], param.name ,tmp[1])
        else:
            define_str = "{}{};".format(param.type_name, param.name)
    elif param.is_array:
        if str(param.complex_type) != '':
            define_str = "{} {};".format(param.complex_type, param.name)
        elif str(param.array_type)[-1] == '*':
            define_str = "{}{}[{}];".format(param.array_type, param.name, param.array_len)
        else:
            define_str = "{} {}[{}];".format(param.array_type, param.name, param.array_len)
    else:
        define_str = "{} {};".format(param.type_name, param.name)
    return define_str

def extractBpOff(dec_list, param_def_str):
    pattern = r"\[sp([\-\+][0-9a-fA-F]+)h\] \[bp([\-\+][0-9a-fA-F]+)h\]"
    for line in dec_list:
        if param_def_str in line:
            matches = re.search(pattern, line)
            if matches:
                sp_off = int(matches.group(1), 16)
                bp_off = int(matches.group(2), 16)
                return (sp_off, bp_off)
            else:
                return None
    return None
```

在controlFlowinator类初始化中添加decompile_str_list属性：
```python
self.decompile_str_list = str(self.cf).split('\n')
```

在get_function_vars()方法中修改my_var_t(v)调用方法。
```python
my_var_t(v, self.decompile_str_list)
```

添加my_var_t类构造方法
```python
	def _init(self, var):
		...
	
    def __init__(self, var, dec_list):
        self._init(var)
        self.has_sp_off = False
        self.has_bp_off = False
        self.sp_off = None
        self.bo_off = None
        self._getStackOff(dec_list)
```

添加my_var_t类方法getStackOff()
```python
    def _getStackOff(self, dec_list):
        param_def_str = getParamDefine(self)
        stack_off = extractBpOff(dec_list, param_def_str)
        if stack_off:
            self.sp_off = stack_off[0]
            self.has_sp_off = True
            self.bp_off = stack_off[1]
            self.has_bp_off = True
```

修改__repr__()打印的方法，添加下面语句：
```python
        if self.has_sp_off:
            print("  sp off: {}".format(self.sp_off))
        if self.has_bp_off:
            print("  bp off: {}".format(self.bp_off))
```

修改get_function_vars()方法
```python
	if only_args:
        return OrderedDict({idx: my_var_t(v, c.decompile_str_list) for idx, v in enumerate(ordered_vars)
                            if v.is_arg_var and v.name})
    elif only_locals:
        return OrderedDict({idx: my_var_t(v, c.decompile_str_list) for idx, v in enumerate(ordered_vars)
                            if not v.is_arg_var and v.name})
    else:
        return OrderedDict({idx: my_var_t(v, c.decompile_str_list) for idx, v in enumerate(ordered_vars)})
```


修改callObj中的部分方法。

修改_populate_args()中的部分
```python
            elif is_var(arg):
                # :class:`var_ref_t` -> :class:`lvar_t` -> :class:`my_var_t`
                lv = ref2var(arg, c=self.c)
                rep = Rep(type='var', val=my_var_t(lv, self.c.decompile_str_list))
```

## 测试代码
```python
import FIDL.decompiler_utils as du

addr1 = 0x17078
addr = 0xCB95C

# get Param defination in IDA
def getParamDefine(param):
    if param.is_pointer:
        if '__fastcall' in param.type_name:
            tmp = param.type_name.split('__fastcall *')
            define_str = "{}__fastcall *{}{};".format(tmp[0], param.name ,tmp[1])
        else:
            define_str = "{}{};".format(param.type_name, param.name)
    elif param.is_array:
        if str(param.complex_type) != '':
            define_str = "{} {};".format(param.complex_type, param.name)
        elif str(param.array_type)[-1] == '*':
            define_str = "{}{}[{}];".format(param.array_type, param.name, param.array_len)
        else:
            define_str = "{} {}[{}];".format(param.array_type, param.name, param.array_len)
    else:
        define_str = "{} {};".format(param.type_name, param.name)
    return define_str

def extractBpOff(dec_list, param_def_str):
    pattern = r"\[sp([\-\+][0-9a-fA-F]+)h\] \[bp([\-\+][0-9a-fA-F]+)h\]"
    for line in dec_list:
        if param_def_str in line:
            matches = re.search(pattern, line)
            if matches:
                sp_off = int(matches.group(1), 16)
                bp_off = int(matches.group(2), 16)
                return (sp_off, bp_off)
            else:
                return None
    return None

cf = du.controlFlowinator(ea=addr, fast=False)
current_function = ida_funcs.get_func(addr)
base_register = ida_frame.get_frame_size(current_function)
#print('base_register:', hex(base_register))


dec_list = str(cf.cf).split('\n')
#print(extractBpOff(dec_list, 'char *s;'))


for lvar in cf.lvars.values():
    param_def_str = getParamDefine(lvar)
    print(param_def_str)
    stack_off = extractBpOff(dec_list, param_def_str)
    if stack_off:
        print("{} // [sp+{}] [bp{}]".format(param_def_str, hex(stack_off[0]), hex(stack_off[1])))
    else:
        print("{}".format(param_def_str))

'''
parma = list(cf.lvars.values())[0]
print(parma.name)
print(parma.is_pointer)
print(parma.is_array)
print(parma.array_type)
print(parma.complex_type)
print(parma.element_size)
print(parma.pointed_type)
print(parma.type_name)
'''

# char *s;
# char s[64]; 
# int i;
# char *var[5];
# va_list va;  --> int *va[1]
# int (__fastcall *v4)(_DWORD, _DWORD, _DWORD, _DWORD);
# struct stat v7; struct sockaddr addr;
# void **s;
```