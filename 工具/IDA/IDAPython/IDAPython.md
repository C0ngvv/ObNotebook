

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

成了
## 第一种模式识别代码
### 逻辑
获取所有函数的交叉引用位于.text的点，并且引用点指令不为类似BL的函数调用指令（使函数指针作为参数）。在交叉引用点向下寻找附近（15条指令内）最近的函数调用指令，然后构建包含调用点函数的cf，进而解析出该函数调用指令的参数，验证：1.参数是否为当前交叉引用的函数指针；2.另外的参数中是否包含字符串参数。如果满足则视为匹配。

同时，统计将函数指针作为函数的函数（可能的注册函数）并记录它门的hit次数。

### 代码
```python
import FIDL.decompiler_utils as du

# take all func addr, there take 0x4F2B0 (fromSysStatusHandle) as an example
#func_addr = 0x4F2B0
call_ins_list = ['BL', 'B', 'BX', 'BLX']

record = []
func_hit_count_record = {}

# get all func
for func_addr in Functions():
    func_name = idc.get_func_name(func_addr)
    if func_name[:1] == '_' or func_name [:1] == '.':
        continue
    #print(func_name)
    # find xref site
    refs = DataRefsTo(func_addr)
    #print(refs)
    for ref in refs:
        seg_type = idc.SegName(ref)
        #print("- 0x{:X}:".format(ref), seg_type)
        if seg_type != ".text":
            continue
    
        # if current ins is bl func, skip
        mnemonic = idc.GetMnem(ref)
        if mnemonic in call_ins_list:
            continue

        # find bl addr within 15 step
        step = 0
        find_bl_flag = False
        ref = NextHead(ref)
        while step < 15:
            mnemonic = idc.GetMnem(ref)
            #print(mnemonic)
            if mnemonic in call_ins_list:
                #print("hit call ins!!", hex(ref))
                find_bl_flag = True
                break
            ref = NextHead(ref)
            step += 1
            pass
        if not find_bl_flag:
            continue
        
        # get current bl params
        # get current func addr and build cf
        #call_site = 0x3FC6C
        call_site = ref
        caller_func = idaapi.get_func(call_site)
        #print("CALL site: ", hex(call_site))
        if caller_func is None:
            continue
        #print("caller func: ", hex(caller_func.start_ea))
        try:
            cf = du.controlFlowinator(ea=caller_func.start_ea, fast=False)
        except Exception as ex:
            print("[ERROR] error in caller func cf")
            continue
        for cf_call in cf.calls:
            # find call_site cf call
            if cf_call.ea == call_site:
                hit = False
                tmpRecord = None
                params = cf_call.args
                for param in params.values():
                    #print(param.val)
                    #print(param.type)
                    if param.type == 'global' and param.val == func_addr:
                        hit = True
                    if param.type == 'string':
                        tmpRecord = param.val
                if not hit or not tmpRecord:
                    continue  # maybe be break
                # record
                if cf_call.name in func_hit_count_record:
                    func_hit_count_record[cf_call.name] += 1
                else:
                    func_hit_count_record[cf_call.name] = 1
                #print([hex(cf_call.ea), cf_call.name, hex(cf_call.call_ea), tmpRecord, hex(func_addr)])
                record.append([hex(cf_call.ea), cf_call.name, hex(cf_call.call_ea), tmpRecord, hex(func_addr)])

print(record)
print(sorted(func_hit_count_record.items(), key=lambda x: x[1], reverse=True))

```

### 输出结果
```
[ERROR] error in caller func cf
[['0xe5e4', 'sub_EC40', '0xec40', 'write', '0xec94'], ['0x2d5c4', 'sub_164C8', '0x164c8', '/goform', '0x15b98'], ['0x2d640', 'sub_164C8', '0x164c8', '/', '0x2d698'], ['0x2d640', 'sub_164C8', '0x164c8', '/', '0x2d698'], ['0x2d5ec', 'sub_164C8', '0x164c8', '/cgi-bin', '0x38e00'], ['0x3fd84', 'sub_EC40', '0xec40', 'aspGetCharset', '0x4140c'], ['0x403c0', 'sub_EC40', '0xec40', 'mNatGetStatic', '0x4146c'], ['0x403dc', 'sub_EC40', '0xec40', 'asp_error_message', '0x418a4'], ['0x403f8', 'sub_EC40', '0xec40', 'asp_error_redirect_url', '0x41904'], ['0x40414', 'sub_EC40', '0xec40', 'mGetIPRate', '0x41964'], ['0x40bd8', 'sub_15D0C', '0x15d0c', 'MfgTest', '0x41d78'], ['0x41180', 'sub_EC40', '0xec40', 'getcfm', '0x41f34'], ['0x4119c', 'sub_15D0C', '0x15d0c', 'setcfm', '0x41ff8'], ['0x41244', 'sub_EC40', '0xec40', 'getifnlist', '0x42590'], ['0x40bbc', 'sub_15D0C', '0x15d0c', 'WriteFacMac', '0x42794'], ['0x3fc50', 'sub_15D0C', '0x15d0c', 'updateUrlLog', '0x4292c'], ['0x41404', 'sub_15D0C', '0x15d0c', 'getRebootStatus', '0x42b0c'], ['0x41404', 'sub_15D0C', '0x15d0c', 'getRebootStatus', '0x42b0c'], ['0x40708', 'sub_15D0C', '0x15d0c', 'SysToolReboot', '0x42c98'], ['0x411d4', 'sub_EC40', '0xec40', 'getModeShow', '0x42f3c'], ['0x411b8', 'sub_EC40', '0xec40', 'getfilterMaxNum', '0x43d34'], ['0x3fc34', 'sub_EC40', '0xec40', 'aspTendaGetStatus', '0x44078'], ['0x3fc18', 'sub_EC40', '0xec40', 'TendaGetLongString', '0x49c1c'], ['0x40724', 'sub_15D0C', '0x15d0c', 'telnet', '0x4aef0'], ['0x41228', 'sub_15D0C', '0x15d0c', 'QuickIndex', '0x4b4e0'], ['0x3fda0', 'sub_15D0C', '0x15d0c', 'WizardHandle', '0x4b9b4'], ['0x3ff60', 'sub_15D0C', '0x15d0c', 'AdvSetLanip', '0x4d3dc'], ['0x3ff44', 'sub_15D0C', '0x15d0c', 'AdvGetLanIp', '0x4db18'], ['0x3fca4', 'sub_15D0C', '0x15d0c', 'GetSysInfo', '0x4ea58'], ['0x3fc88', 'sub_15D0C', '0x15d0c', 'GetWanStatus', '0x4f084'], ['0x3fc6c', 'sub_15D0C', '0x15d0c', 'SysStatusHandle', '0x4f2b0'], ['0x3fcc0', 'sub_15D0C', '0x15d0c', 'GetWanStatistic', '0x4f484'], ['0x3fcdc', 'sub_15D0C', '0x15d0c', 'GetAllWanInfo', '0x4f764'], ['0x3fcf8', 'sub_15D0C', '0x15d0c', 'GetWanNum', '0x4fb14'], ['0x3fd14', 'sub_EC40', '0xec40', 'aspGetWanNum', '0x4fb78'], ['0x4120c', 'sub_EC40', '0xec40', 'getMaxNatNum', '0x4fbdc'], ['0x3fd30', 'sub_15D0C', '0x15d0c', 'getPortStatus', '0x4fc54'], ['0x3fd4c', 'sub_15D0C', '0x15d0c', 'GetSystemStatus', '0x51130'], ['0x405b8', 'sub_15D0C', '0x15d0c', 'setBlackRule', '0x54670'], ['0x405d4', 'sub_15D0C', '0x15d0c', 'delBlackRule', '0x55218'], ['0x405f0', 'sub_15D0C', '0x15d0c', 'getBlackRuleList', '0x555d8'], ['0x3fd68', 'sub_15D0C', '0x15d0c', 'GetRouterStatus', '0x559b8'], ['0x40238', 'sub_15D0C', '0x15d0c', 'getOnlineList', '0x56974'], ['0x404f4', 'sub_15D0C', '0x15d0c', 'GetDeviceDetail', '0x57438'], ['0x4052c', 'sub_15D0C', '0x15d0c', 'SetOnlineDevName', '0x581a0'], ['0x40510', 'sub_15D0C', '0x15d0c', 'SetClientState', '0x583c8'], ['0x40564', 'sub_15D0C', '0x15d0c', 'SetSpeedWan', '0x58738'], ['0x413e8', 'sub_15D0C', '0x15d0c', 'GetSysStatus', '0x58a88'], ['0x40254', 'sub_15D0C', '0x15d0c', 'GetAdvanceStatus', '0x5912c'], ['0x404bc', 'sub_15D0C', '0x15d0c', 'SetNetControlList', '0x59748'], ['0x404d8', 'sub_15D0C', '0x15d0c', 'GetNetControlList', '0x5998c'], ['0x3fdbc', 'sub_15D0C', '0x15d0c', 'fast_setting_get', '0x5a4e4'], ['0x3fdd8', 'sub_15D0C', '0x15d0c', 'fast_setting_pppoe_get', '0x5a8e4'], ['0x3fe2c', 'sub_15D0C', '0x15d0c', 'getWanConnectStatus', '0x5ab00'], ['0x3fe10', 'sub_15D0C', '0x15d0c', 'fast_setting_pppoe_set', '0x5ae48'], ['0x3fdf4', 'sub_15D0C', '0x15d0c', 'fast_setting_wifi_set', '0x5b010'], ['0x3fe48', 'sub_15D0C', '0x15d0c', 'getProduct', '0x5b990'], ['0x3fe64', 'sub_15D0C', '0x15d0c', 'usb_get', '0x5bc4c'], ['0x40b84', 'sub_15D0C', '0x15d0c', 'ate', '0x5fd00'], ['0x3ff7c', 'sub_15D0C', '0x15d0c', 'SetWebIpAccess', '0x5fd54'], ['0x3ff98', 'sub_15D0C', '0x15d0c', 'WanPolicy', '0x5feb4'], ['0x3ff0c', 'sub_15D0C', '0x15d0c', 'AdvSetMTU', '0x60768'], ['0x3ff28', 'sub_15D0C', '0x15d0c', 'AdvGetMTU', '0x60938'], ['0x40040', 'sub_15D0C', '0x15d0c', 'WanParameterSetting', '0x60b34'], ['0x4005c', 'sub_15D0C', '0x15d0c', 'getWanParameters', '0x61ba8'], ['0x40078', 'sub_15D0C', '0x15d0c', 'wanNumSet', '0x64a3c'], ['0x40094', 'sub_15D0C', '0x15d0c', 'getAdvanceStatus', '0x64ba4'], ['0x3fef0', 'sub_15D0C', '0x15d0c', 'AdvSetMacMtuWan', '0x65800'], ['0x3fed4', 'sub_15D0C', '0x15d0c', 'AdvGetMacMtuWan', '0x65dc8'], ['0x3ffb4', 'sub_15D0C', '0x15d0c', 'SetRemoteWebCfg', '0x66268'], ['0x3ffd0', 'sub_15D0C', '0x15d0c', 'GetRemoteWebCfg', '0x664a4'], ['0x402a8', 'sub_15D0C', '0x15d0c', 'SetDMZCfg', '0x66750'], ['0x402c4', 'sub_15D0C', '0x15d0c', 'GetDMZCfg', '0x66948'], ['0x3ffec', 'sub_15D0C', '0x15d0c', 'WanPortParam', '0x66c74'], ['0x40008', 'sub_15D0C', '0x15d0c', 'AdvSetMacClone', '0x66e78'], ['0x40024', 'sub_15D0C', '0x15d0c', 'AdvGetMacClone', '0x67274'], ['0x40270', 'sub_15D0C', '0x15d0c', 'SetVirtualServerCfg', '0x683f8'], ['0x4028c', 'sub_15D0C', '0x15d0c', 'GetVirtualServerCfg', '0x68518'], ['0x40318', 'sub_15D0C', '0x15d0c', 'NatStaticSetting', '0x68850'], ['0x40484', 'sub_EC40', '0xec40', 'NatSet', '0x689f8'], ['0x40468', 'sub_15D0C', '0x15d0c', 'AdvSetNat', '0x68abc'], ['0x40334', 'sub_15D0C', '0x15d0c', 'SetDDNSCfg', '0x68b88'], ['0x40350', 'sub_15D0C', '0x15d0c', 'GetDDNSCfg', '0x692b4'], ['0x4036c', 'sub_EC40', '0xec40', 'mGetRouteTable', '0x69614'], ['0x40388', 'sub_15D0C', '0x15d0c', 'RouteStatic', '0x697b0'], ['0x403a4', 'sub_15D0C', '0x15d0c', 'addressNat', '0x69c6c'], ['0x406b4', 'sub_15D0C', '0x15d0c', 'SysToolSysLog', '0x69e00'], ['0x40698', 'sub_15D0C', '0x15d0c', 'GetSySLogCfg', '0x69e5c'], ['0x406d0', 'sub_15D0C', '0x15d0c', 'LogsSetting', '0x6a1b8'], ['0x40740', 'sub_15D0C', '0x15d0c', 'SysToolRestoreSet', '0x6a334'], ['0x3fe80', 'sub_15D0C', '0x15d0c', 'SysToolpassword', '0x6a388'], ['0x4075c', 'sub_15D0C', '0x15d0c', 'SysToolChangePwd', '0x6a45c'], ['0x40778', 'sub_15D0C', '0x15d0c', 'SysToolBaseUser', '0x6a798'], ['0x40548', 'sub_15D0C', '0x15d0c', 'GetSystemSet', '0x6a990'], ['0x40794', 'sub_15D0C', '0x15d0c', 'SysToolGetUpgrade', '0x6aaa8'], ['0x407b0', 'sub_15D0C', '0x15d0c', 'SysToolSetUpgrade', '0x6ab9c'], ['0x40ba0', 'sub_15D0C', '0x15d0c', 'exeCommand', '0x6b558'], ['0x40644', 'sub_15D0C', '0x15d0c', 'initAutoQos', '0x6d8cc'], ['0x40660', 'sub_15D0C', '0x15d0c', 'saveAutoQos', '0x6db98'], ['0x4067c', 'sub_15D0C', '0x15d0c', 'getQosSpeed', '0x6dd54'], ['0x40158', 'sub_15D0C', '0x15d0c', 'GetParentControlInfo', '0x70fcc'], ['0x40174', 'sub_15D0C', '0x15d0c', 'saveParentControlInfo', '0x7304c'], ['0x40580', 'sub_15D0C', '0x15d0c', 'getParentalRuleList', '0x74054'], ['0x4059c', 'sub_15D0C', '0x15d0c', 'delParentalRule', '0x744fc'], ['0x404a0', 'sub_15D0C', '0x15d0c', 'GetParentCtrlList', '0x74e94'], ['0x402fc', 'sub_15D0C', '0x15d0c', 'SetUpnpCfg', '0x756fc'], ['0x402e0', 'sub_15D0C', '0x15d0c', 'GetUpnpCfg', '0x75828'], ['0x401ac', 'sub_15D0C', '0x15d0c', 'DhcpSetSer', '0x75af8'], ['0x40190', 'sub_15D0C', '0x15d0c', 'GetDhcpServer', '0x760d8'], ['0x401e4', 'sub_15D0C', '0x15d0c', 'DhcpListClient', '0x76484'], ['0x401c8', 'sub_EC40', '0xec40', 'TendaGetDhcpClients', '0x766dc'], ['0x4021c', 'sub_EC40', '0xec40', 'TendaGetDhcpClients', '0x766dc'], ['0x40200', 'sub_15D0C', '0x15d0c', 'ajaxTendaGetDhcpClients', '0x77008'], ['0x411f0', 'sub_15D0C', '0x15d0c', 'ajaxTendaGetGuestDhcpClients', '0x77404'], ['0x406ec', 'sub_15D0C', '0x15d0c', 'SysToolTime', '0x7781c'], ['0x41298', 'sub_15D0C', '0x15d0c', 'SetSysTimeCfg', '0x77cf0'], ['0x412b4', 'sub_15D0C', '0x15d0c', 'GetSysTimeCfg', '0x7827c'], ['0x40104', 'sub_15D0C', '0x15d0c', 'openSchedWifi', '0x78b74'], ['0x400e8', 'sub_15D0C', '0x15d0c', 'initSchedWifi', '0x790fc'], ['0x4013c', 'sub_15D0C', '0x15d0c', 'SetLEDCfg', '0x79948'], ['0x40120', 'sub_15D0C', '0x15d0c', 'GetLEDCfg', '0x79ca0'], ['0x4044c', 'sub_15D0C', '0x15d0c', 'BulletinSet', '0x7a060'], ['0x40430', 'sub_15D0C', '0x15d0c', 'AdvSetPortVlan', '0x7a28c'], ['0x41164', 'sub_EC40', '0xec40', 'GetPortShow', '0x7a318'], ['0x407cc', 'sub_15D0C', '0x15d0c', 'WifiMultiSsid', '0x7ae18'], ['0x407e8', 'sub_15D0C', '0x15d0c', 'WifiBasicGet', '0x7b348'], ['0x40804', 'sub_15D0C', '0x15d0c', 'WifiBasicSet', '0x7c430'], ['0x40820', 'sub_15D0C', '0x15d0c', 'WifiApScan', '0x7d828'], ['0x4083c', 'sub_15D0C', '0x15d0c', 'WifiClientList', '0x7f078'], ['0x40858', 'sub_15D0C', '0x15d0c', 'WifiClientListAll', '0x7f318'], ['0x408ac', 'sub_15D0C', '0x15d0c', 'initWifiMacFilter', '0x7f57c'], ['0x408c8', 'sub_15D0C', '0x15d0c', 'addWifiMacFilter', '0x7fe00'], ['0x408e4', 'sub_15D0C', '0x15d0c', 'delWifiMacFilter', '0x80238'], ['0x40874', 'sub_15D0C', '0x15d0c', 'WifiMacFilterGet', '0x80670'], ['0x40890', 'sub_15D0C', '0x15d0c', 'WifiMacFilterSet', '0x80c08'], ['0x40900', 'sub_15D0C', '0x15d0c', 'WifiRadioGet', '0x811a4'], ['0x4091c', 'sub_15D0C', '0x15d0c', 'WifiRadioSet', '0x8160c'], ['0x40954', 'sub_15D0C', '0x15d0c', 'WifiPowerSet', '0x82654'], ['0x40938', 'sub_15D0C', '0x15d0c', 'WifiPowerGet', '0x82ce4'], ['0x40970', 'sub_15D0C', '0x15d0c', 'WifiStatistic', '0x82e54'], ['0x4098c', 'sub_15D0C', '0x15d0c', 'WifiStatisticClear', '0x83538'], ['0x409a8', 'sub_15D0C', '0x15d0c', 'WifiDhcpGuestGet', '0x835b0'], ['0x409c4', 'sub_15D0C', '0x15d0c', 'WifiDhcpGuestLists', '0x837d8'], ['0x409e0', 'sub_15D0C', '0x15d0c', 'WifiDhcpGuestSet', '0x83c70'], ['0x409fc', 'sub_15D0C', '0x15d0c', 'WifiStatus', '0x8403c'], ['0x40a6c', 'sub_15D0C', '0x15d0c', 'WifiConfigGet', '0x848f0'], ['0x40a34', 'sub_15D0C', '0x15d0c', 'WifiWpsStart', '0x84a28'], ['0x40a50', 'sub_15D0C', '0x15d0c', 'WifiWpsOOB', '0x85e34'], ['0x40aa4', 'sub_15D0C', '0x15d0c', 'WifiWpsSet', '0x86784'], ['0x40ac0', 'sub_15D0C', '0x15d0c', 'WifiWpsStart', '0x86958'], ['0x40a88', 'sub_15D0C', '0x15d0c', 'WifiWpsGet', '0x86a90'], ['0x41308', 'sub_15D0C', '0x15d0c', 'WifiGuestSet', '0x8a1e0'], ['0x41324', 'sub_15D0C', '0x15d0c', 'WifiGuestGet', '0x8a5c4'], ['0x412d0', 'sub_15D0C', '0x15d0c', 'WifiExtraSet', '0x8b078'], ['0x412ec', 'sub_15D0C', '0x15d0c', 'WifiExtraGet', '0x8cd70'], ['0x41340', 'sub_15D0C', '0x15d0c', 'GetWrlStatus', '0x8dd10'], ['0x40adc', 'sub_15D0C', '0x15d0c', 'SetPrinterCfg', '0x8e540'], ['0x40af8', 'sub_15D0C', '0x15d0c', 'GetPrinterCfg', '0x8e66c'], ['0x40b14', 'sub_15D0C', '0x15d0c', 'SetSambaCfg', '0x8e720'], ['0x40b30', 'sub_15D0C', '0x15d0c', 'GetSambaCfg', '0x8ea40'], ['0x3fe9c', 'sub_15D0C', '0x15d0c', 'cloud', '0x95114'], ['0x3feb8', 'sub_15D0C', '0x15d0c', 'onlineupgrade', '0x95cb8'], ['0x40a18', 'sub_15D0C', '0x15d0c', 'getAliWifiScheduled', '0x960a0'], ['0x4060c', 'sub_15D0C', '0x15d0c', 'SetIPTVCfg', '0x9683c'], ['0x40628', 'sub_15D0C', '0x15d0c', 'GetIPTVCfg', '0x96cdc'], ['0x40b68', 'sub_15D0C', '0x15d0c', 'GetDlnaCfg', '0x9723c'], ['0x40b4c', 'sub_15D0C', '0x15d0c', 'SetDlnaCfg', '0x9735c'], ['0x41260', 'sub_15D0C', '0x15d0c', 'SetSysAutoRebbotCfg', '0x9764c'], ['0x4127c', 'sub_15D0C', '0x15d0c', 'GetSysAutoRebbotCfg', '0x977e0'], ['0x400b0', 'sub_15D0C', '0x15d0c', 'PowerSaveGet', '0x97ce0'], ['0x400cc', 'sub_15D0C', '0x15d0c', 'PowerSaveSet', '0x984d8'], ['0x4135c', 'sub_15D0C', '0x15d0c', 'SetPptpServerCfg', '0x9b638'], ['0x41378', 'sub_15D0C', '0x15d0c', 'GetPptpServerCfg', '0x9c884'], ['0x41394', 'sub_15D0C', '0x15d0c', 'SetPptpClientCfg', '0x9d34c'], ['0x413b0', 'sub_15D0C', '0x15d0c', 'GetPptpClientCfg', '0x9dadc'], ['0x413cc', 'sub_15D0C', '0x15d0c', 'GetVpnStatus', '0x9e564']]
[('sub_15D0C', 153), ('sub_EC40', 19), ('sub_164C8', 4)]
```

## 第二种模式识别代码
### 逻辑
遍历所有函数，寻找交叉引用位于.data位置的点，判断上一个数据是否为字符串类型，是则视为匹配，进行记录。

同时获取该表的头和尾部分（向前或向后遍历直到数据为0x0），并统计每次匹配hit该表的次数。

![](images/Pasted%20image%2020231120221155.png)

### 代码
```

records = []
# {table_head:}
table_records = {}
'''
{
    start_addr:
        {
        start_addr: 0xD2470,
        end_addr: 0xd2c8c,
        hit_count: 1,
        }
}
'''

# func_addr = 0x300F0
for func_addr in Functions():
    refs = DataRefsTo(func_addr)
    func_name = idc.get_func_name(func_addr)
    for ref in refs:
        seg_type = idc.SegName(ref)
        #print(hex(ref), seg_type)
        if seg_type != ".data":
            continue
        #print(idc.print_operand(ref, 0))
    
        # whether the previous address is a string
        preAddr = PrevHead(ref)
        originData = idc.get_wide_dword(preAddr)
        # is a valid addr?
        if not idaapi.is_loaded(originData):
            continue
        flags = idaapi.get_flags(originData)
        if not ida_bytes.is_strlit(flags):
            continue
        url_str = idc.GetString(originData)
        # [xref_site, str_addr, str, func_addr, func_name]
        records.append([hex(ref), hex(originData), url_str, hex(func_addr), func_name])
        print([hex(ref), hex(originData), url_str, hex(func_addr), func_name])
    
        # if hit table
        is_hit_table = False
        for table_key in table_records:
            if ref >= table_records[table_key]['head_addr'] and ref <= table_records[table_key]['tail_addr']:
                table_records[table_key]['hit_count'] += 1
                is_hit_table = True
                break
        if not is_hit_table:    
            # first hit table, find head and tail, add table info
            preAddr = PrevHead(ref)
            while idc.get_wide_dword(preAddr):
                preAddr = PrevHead(preAddr)
            table_head_addr = NextHead(preAddr)
        
            nextAddr = NextHead(ref)
            while idc.get_wide_dword(nextAddr):
                nextAddr = NextHead(nextAddr)
            table_tail_addr = PrevHead(nextAddr)
            
            # print(hex(table_head_addr), hex(table_tail_addr))
        
            table = {}
            table['head_addr'] = table_head_addr
            table['tail_addr'] = table_tail_addr
            table['hit_count'] = 1
            table_records[str(hex(table_head_addr))] = table

#print(records)
print("table_records")
for table_key in table_records:
    print(hex(table_records[table_key]['head_addr']), hex(table_records[table_key]['tail_addr']), table['hit_count'])

```

### 输出结果
```
['0xd26d4', '0x8135a', b'script_get', '0x14a68', 'sub_14A68']
['0xd26cc', '0x81351', b'meta_get', '0x14ad0', 'sub_14AD0']
['0xd2494', '0x80cde', b'nvram_list', '0x14b38', 'sub_14B38']
['0xd248c', '0x80ccf', b'nvram_invmatch', '0x14c58', 'sub_14C58']
['0xd2484', '0x80cc3', b'nvram_match', '0x14ca0', 'sub_14CA0']
['0xd25e4', '0x810c3', b'delayTimeGet', '0x14e8c', 'sub_14E8C']
['0xd2704', '0x813da', b'access_mac_get', '0x14ed4', 'sub_14ED4']
['0xd26f4', '0x813ba', b'pot_value_get', '0x14f1c', 'sub_14F1C']
['0xd26fc', '0x813c8', b'ntp_sync_time_get', '0x14f78', 'sub_14F78']
['0xd247c', '0x80cb9', b'nvram_get', '0x15158', 'sub_15158']
['0xd266c', '0x81253', b'option_get', '0x1592c', 'sub_1592C']
['0xd2654', '0x811e7', b'devices_cgi_get_device_table_wired', '0x18a4c', 'sub_18A4C']
['0xd265c', '0x8120a', b'devices_cgi_get_device_table_wireless', '0x19154', 'sub_19154']
['0xd2d7c', '0x825d2', b'devices.cgi', '0x19174', 'sub_19174']
['0xd2c54', '0x82408', b'devices_cgi_get_redirect_page', '0x191e0', 'sub_191E0']
['0xd2664', '0x81230', b'devices_cgi_get_access_ctrl_enable', '0x191fc', 'sub_191FC']
['0xd2d8c', '0x6de8b', b'backup.cgi', '0x1ab80', 'sub_1AB80']
['0xd3034', '0x6de96', b'genierestore.cgi', '0x1ad08', 'sub_1AD08']
['0xd256c', '0x80f52', b'basic_cgi_get_param', '0x1b220', 'sub_1B220']
['0xd2584', '0x80f98', b'get_test_link', '0x1b6f8', 'sub_1B6F8']
['0xd2ed4', '0x827a2', b'pppoe2.cgi', '0x1c9b4', 'sub_1C9B4']
['0xd2edc', '0x827ad', b'pppoe2_domain.cgi', '0x1d1b8', 'sub_1D1B8']
['0xd2ee4', '0x827bf', b'pppoe2_ip.cgi', '0x1d24c', 'sub_1D24C']
['0xd2eec', '0x827cd', b'pppoe2_port.cgi', '0x1d380', 'sub_1D380']
['0xd25d4', '0x81087', b'basic_cgi_get_pppoe2_policy_table', '0x1d4a4', 'sub_1D4A4']
['0xd2cdc', '0x82519', b'wiz_dyn.cgi', '0x1e0c4', 'sub_1E0C4']
['0xd2ce4', '0x82525', b'wizpppoe.cgi', '0x1e21c', 'sub_1E21C']
['0xd2cec', '0x82532', b'wiz_fix2.cgi', '0x1e740', 'sub_1E740']
['0xd2cf4', '0x8253f', b'wiz_pptp.cgi', '0x1e978', 'sub_1E978']
['0xd25dc', '0x810a9', b'basic_cgi_get_24hr_status', '0x1efac', 'sub_1EFAC']
['0xd303c', '0x82a62', b'genie_dyn.cgi', '0x1efe8', 'sub_1EFE8']
['0xd3044', '0x82a70', b'geniepppoe.cgi', '0x1f0ec', 'sub_1F0EC']
['0xd304c', '0x82a7f', b'genie_fix2.cgi', '0x1f5a8', 'sub_1F5A8']
['0xd305c', '0x82a9c', b'genie_pptp.cgi', '0x1f7dc', 'sub_1F7DC']
['0xd3054', '0x82a8e', b'genie_bpa.cgi', '0x1fc6c', 'sub_1FC6C']
['0xd3064', '0x82aab', b'genieether.cgi', '0x1fe30', 'sub_1FE30']
['0xd2b0c', '0x81fba', b'newgui_get_wan_setup_icon', '0x1fed0', 'sub_1FED0']
['0xd2b14', '0x81fd4', b'newgui_get_wireless_setup_icon', '0x1ff4c', 'sub_1FF4C']
['0xd2b1c', '0x81ff3', b'newgui_get_guest_setup_icon', '0x20010', 'sub_20010']
['0xd2b24', '0x8200f', b'newgui_basic_cgi_get_wan_macaddr', '0x20180', 'sub_20180']
['0xd2b2c', '0x82030', b'newgui_basic_cgi_get_wan_ip', '0x201a8', 'sub_201A8']
['0xd2b3c', '0x8206d', b'newgui_basic_cgi_get_dns_server', '0x20274', 'sub_20274']
['0xd2b44', '0x8208d', b'newgui_basic_cgi_get_lan_mac', '0x20330', 'sub_20330']
['0xd2b4c', '0x820aa', b'newgui_basic_cgi_get_lan_ipaddr', '0x20354', 'sub_20354']
['0xd2b54', '0x820ca', b'newgui_basic_cgi_get_lan_netmask', '0x20378', 'sub_20378']
['0xd2d04', '0x82559', b'ddns.cgi', '0x2039c', 'sub_2039C']
['0xd264c', '0x811d2', b'ddns_cgi_show_status', '0x205cc', 'sub_205CC']
['0xd2554', '0x80f17', b'access_cgi_get_userip', '0x20818', 'sub_20818']
['0xd2564', '0x80f3f', b'access_cgi_get_pic', '0x20980', 'sub_20980']
['0xd255c', '0x80f2d', b'access_cgi_logout', '0x20eb0', 'sub_20EB0']
['0xd2dac', '0x6d123', b'ptimeout.cgi', '0x212c8', 'sub_212C8']
['0xd30a4', '0x6cca2', b'multi_login.cgi', '0x2144c', 'sub_2144C']
['0xd2cac', '0x824da', b'fwLog.cgi', '0x215ac', 'sub_215AC']
['0xd261c', '0x8114e', b'fw_cgi_get_log_param', '0x217c8', 'sub_217C8']
['0xd2cb4', '0x824e4', b'fwEmail.cgi', '0x22084', 'sub_22084']
['0xd2624', '0x81163', b'fw_cgi_get_mail_param', '0x22554', 'sub_22554']
['0xd28a4', '0x81822', b'upgrade_cgi_get_param', '0x22f4c', 'sub_22F4C']
['0xd2ca4', '0x6d6d2', b'upgrade_check.cgi', '0x23210', 'sub_23210']
['0xd2c9c', '0x8269a', b'upgrade.cgi', '0x23608', 'sub_23608']
['0xd24b4', '0x80d30', b'lan_cgi_get_rsvip_table', '0x23b24', 'sub_23B24']
['0xd24bc', '0x80d48', b'lan_cgi_get_rsvip_param', '0x23cc4', 'sub_23CC4']
['0xd24c4', '0x80d60', b'lan_cgi_get_attach_device_table', '0x23d5c', 'sub_23D5C']
['0xd2d14', '0x8256f', b'lan.cgi', '0x243b8', 'sub_243B8']
['0xd2d1c', '0x82577', b'reserv.cgi', '0x248f8', 'sub_248F8']
['0xd24cc', '0x80d80', b'resp_cgi_get', '0x25158', 'sub_25158']
['0xd24d4', '0x80d8d', b'rst_cgi_get_fw_version', '0x259c8', 'sub_259C8']
['0xd24dc', '0x80da4', b'rst_cgi_get_hw_version', '0x259f4', 'sub_259F4']
['0xd24ec', '0x80dcd', b'rst_cgi_get_dhcpc_param', '0x261a8', 'sub_261A8']
['0xd24f4', '0x80de5', b'rst_cgi_get_pppoe_connect_time', '0x262f8', 'sub_262F8']
['0xd2504', '0x80e1d', b'rst_cgi_get_login_connect_time', '0x26324', 'sub_26324']
['0xd24fc', '0x80e04', b'rst_cgi_get_pppoe_status', '0x263c4', 'sub_263C4']
['0xd2514', '0x80e55', b'rst_cgi_test_internet_connection', '0x264ec', 'sub_264EC']
['0xd250c', '0x80e3c', b'rst_cgi_get_login_status', '0x2658c', 'sub_2658C']
['0xd2534', '0x80eb1', b'rst_cgi_get_wan_param', '0x267cc', 'sub_267CC']
['0xd253c', '0x80ec7', b'rst_cgi_get_static_ip_param', '0x27130', 'sub_27130']
['0xd252c', '0x80e9a', b'rst_cgi_get_pptp_param', '0x271d8', 'sub_271D8']
['0xd258c', '0x80fa6', b'rst_cgi_get_l2tp_param', '0x27298', 'sub_27298']
['0xd2d5c', '0x825a6', b'st_dhcp.cgi', '0x27358', 'sub_27358']
['0xd2d6c', '0x825bd', b'st_pptp.cgi', '0x27a18', 'sub_27A18']
['0xd2d44', '0x82582', b'st_l2tp.cgi', '0x27b08', 'sub_27B08']
['0xd259c', '0x80fd7', b'rst_cgi_get_pppoe2_netmask', '0x27cfc', 'sub_27CFC']
['0xd2594', '0x80fbd', b'rst_cgi_get_pppoe2_ipaddr', '0x27d3c', 'sub_27D3C']
['0xd25a4', '0x80ff2', b'rst_cgi_get_pppoe2_dns', '0x27d7c', 'sub_27D7C']
['0xd25ac', '0x81009', b'rst_cgi_get_flet_status', '0x27eec', 'sub_27EEC']
['0xd25b4', '0x81021', b'rst_cgi_get_flet_type', '0x280e4', 'sub_280E4']
['0xd25bc', '0x81037', b'rst_cgi_get_pppoe2_connect_time', '0x2818c', 'sub_2818C']
['0xd2d64', '0x825b2', b'st_poe.cgi', '0x28460', 'sub_28460']
['0xd24e4', '0x80dbb', b'rst_cgi_get_stats', '0x28894', 'sub_28894']
['0xd2c4c', '0x823fa', b'rst_get_param', '0x290f8', 'sub_290F8']
['0xd2f14', '0x82832', b'pppoe2_keyword.cgi', '0x29dec', 'sub_29DEC']
['0xd2cfc', '0x8254c', b'password.cgi', '0x2a448', 'sub_2A448']
['0xd3084', '0x6cc5d', b'unauth.cgi', '0x2a658', 'sub_2A658']
['0xd309c', '0x6cc94', b'userlogin.cgi', '0x2a698', 'sub_2A698']
['0xd308c', '0x6cc68', b'securityquestions.cgi', '0x2a818', 'sub_2A818']
['0xd3094', '0x6cc7e', b'passwordrecovered.cgi', '0x2a8a4', 'sub_2A8A4']
['0xd2c1c', '0x82382', b'check_is_index', '0x2ad44', 'sub_2AD44']
['0xd2544', '0x80ee3', b'route_cgi_get_route_table', '0x2afec', 'sub_2AFEC']
['0xd254c', '0x80efd', b'route_cgi_get_route_param', '0x2b158', 'sub_2B158']
['0xd2d4c', '0x8258e', b'routes.cgi', '0x2b2dc', 'sub_2B2DC']
['0xd2d54', '0x82599', b'routinfo.cgi', '0x2b5e4', 'sub_2B5E4']
['0xd262c', '0x81179', b'fw_cgi_get_inbound_param', '0x2c578', 'sub_2C578']
['0xd2cbc', '0x824f0', b'pforward.cgi', '0x2ded4', 'sub_2DED4']
['0xd26ec', '0x8139b', b'fw_cgi_get_attach_device_table', '0x2f490', 'sub_2F490']
['0xd2574', '0x80f66', b'russia_specific_support', '0x2f724', 'sub_2F724']
['0xd2d0c', '0x82562', b'security.cgi', '0x2f9d8', 'sub_2F9D8']
['0xd249c', '0x80ce9', b'wiz_cgi_sel_get_next', '0x300f0', 'sub_300F0']
['0xd24a4', '0x80cfe', b'wiz_cgi_result_get_next', '0x30164', 'sub_30164']
['0xd24ac', '0x80d16', b'wiz_cgi_result_get_result', '0x30214', 'sub_30214']
['0xd267c', '0x8125e', b'fw_cgi_get_service_array', '0x31a10', 'sub_31A10']
['0xd2684', '0x81277', b'fw_cgi_get_service_list', '0x31c10', 'sub_31C10']
['0xd268c', '0x8128f', b'fw_cgi_get_selected_service_list', '0x31d18', 'sub_31D18']
['0xd2694', '0x812b0', b'fw_cgi_get_ip_type_status', '0x31f6c', 'sub_31F6C']
['0xd269c', '0x812ca', b'fw_cgi_get_ip_single_ip', '0x32044', 'sub_32044']
['0xd26a4', '0x812e2', b'fw_cgi_get_ip_range_sip', '0x32180', 'sub_32180']
['0xd26ac', '0x812fa', b'fw_cgi_get_ip_range_eip', '0x322cc', 'sub_322CC']
['0xd26b4', '0x81312', b'fw_cgi_get_lan_ip', '0x32418', 'sub_32418']
['0xd26bc', '0x81324', b'fw_cgi_get_err_reason', '0x324f4', 'sub_324F4']
['0xd26c4', '0x8133a', b'fw_cgi_get_return_page', '0x32510', 'sub_32510']
['0xd2efc', '0x827f0', b'pppoe2_fw_serv.cgi', '0x34428', 'sub_34428']
['0xd25fc', '0x810ff', b'flet_serv_get_param', '0x3484c', 'sub_3484C']
['0xd2f04', '0x82803', b'pppoe2_fw_serv_add.cgi', '0x348f4', 'sub_348F4']
['0xd2f0c', '0x8281a', b'pppoe2_fw_serv_edit.cgi', '0x34f40', 'sub_34F40']
['0xd2604', '0x81113', b'pppoe2_fw_cgi_get_bks_table', '0x3588c', 'sub_3588C']
['0xd2634', '0x81192', b'fw_cgi_get_daytime_param', '0x35a84', 'sub_35A84']
['0xd2cc4', '0x824fd', b'fwSchedule.cgi', '0x35fd0', 'sub_35FD0']
['0xd25f4', '0x810df', b'fw_cgi_get_daytime_param_pppoe2', '0x362e8', 'sub_362E8']
['0xd2ccc', '0x8250c', b'fwRemote.cgi', '0x36a28', 'sub_36A28']
['0xd263c', '0x811ab', b'fw_get_remote_param', '0x36dcc', 'sub_36DCC']
['0xd26dc', '0x81365', b'fw_cgi_pt_get_policy_table', '0x393b0', 'sub_393B0']
['0xd26e4', '0x81380', b'fw_cgi_pt_get_policy_param', '0x396e4', 'sub_396E4']
['0xd2dbc', '0x825e7', b'fwpt_service.cgi', '0x39dac', 'sub_39DAC']
['0xd2db4', '0x825de', b'fwpt.cgi', '0x3a454', 'sub_3A454']
['0xd2a24', '0x81ca6', b'mnu_cgi_get_document_page', '0x3ab74', 'sub_3AB74']
['0xd29f4', '0x81c06', b'mnu_cgi_get_wireless_page', '0x3ab90', 'sub_3AB90']
['0xd29fc', '0x81c20', b'mnu_cgi_get_adv_wireless_page', '0x3abac', 'sub_3ABAC']
['0xd2a04', '0x81c3e', b'mnu_cgi_get_guest_wireless_page', '0x3abec', 'sub_3ABEC']
['0xd2a0c', '0x81c5e', b'mnu_cgi_get_wds_page', '0x3ac08', 'sub_3AC08']
['0xd2a14', '0x81c73', b'mnu_cgi_get_router_status_page', '0x3ac24', 'sub_3AC24']
['0xd2614', '0x8113c', b'blk_cgi_get_param', '0x3afec', 'sub_3AFEC']
['0xd2dc4', '0x825f8', b'bsw_dhcp.cgi', '0x3b270', 'sub_3B270']
['0xd2de4', '0x8262c', b'bas_detwan.cgi', '0x3b440', 'sub_3B440']
['0xd2dcc', '0x82605', b'bsw_pppoe.cgi', '0x3b4d8', 'sub_3B4D8']
['0xd2dd4', '0x82613', b'bsw_pptp.cgi', '0x3b94c', 'sub_3B94C']
['0xd2ddc', '0x82620', b'bsw_fix.cgi', '0x3bbb8', 'sub_3BBB8']
['0xd2e9c', '0x82752', b'blkGetResult.cgi', '0x3bea0', 'sub_3BEA0']
['0xd285c', '0x8176a', b'isLanWanConflict', '0x3bf0c', 'sub_3BF0C']
['0xd286c', '0x8178e', b'blkcgi_update_conflict_flag', '0x3c068', 'sub_3C068']
['0xd2874', '0x817aa', b'blkcgi_get_conflict_hijack_page', '0x3c0d4', 'sub_3C0D4']
['0xd2864', '0x8177b', b'lipchanged_getpage', '0x3c19c', 'sub_3C19C']
['0xd25ec', '0x810d0', b'flet_get_param', '0x3c348', 'sub_3C348']
['0xd260c', '0x8112f', b'is_jp_region', '0x3c454', 'sub_3C454']
['0xd2dec', '0x8263b', b'wireless.cgi', '0x3d0d4', 'sub_3D0D4']
['0xd30dc', '0x82b5a', b'bridge_wireless_main.cgi', '0x3e6b4', 'sub_3E6B4']
['0xd2df4', '0x82648', b'wlan_acl.cgi', '0x3eec0', 'sub_3EEC0']
['0xd2dfc', '0x82655', b'wlan_acl_add.cgi', '0x3f09c', 'sub_3F09C']
['0xd2e04', '0x82666', b'wlan_acl_edit.cgi', '0x3f174', 'sub_3F174']
['0xd2824', '0x816e7', b'get_tmp_dev', '0x3f270', 'sub_3F270']
['0xd271c', '0x8140c', b'wlg_cgi_opmode_get', '0x3f2c0', 'sub_3F2C0']
['0xd2744', '0x8146a', b'wlg_cgi_get_secutype', '0x3f590', 'sub_3F590']
['0xd2c8c', '0x824c5', b'wds_fail_return_page', '0x3f5c4', 'sub_3F5C4']
['0xd27bc', '0x815b3', b'wlg_cgi_get_wlanstate_status', '0x3f634', 'sub_3F634']
['0xd2784', '0x8151a', b'wlg_cgi_get_suppressssid_status', '0x3f6f0', 'sub_3F6F0']
['0xd2c5c', '0x82426', b'wlg_cgi_get_coexist_status', '0x3f7e0', 'sub_3F7E0']
['0xd280c', '0x8169d', b'wlg_cgi_get_wps_state', '0x3f844', 'sub_3F844']
['0xd273c', '0x81455', b'wlg_cgi_get_authtype', '0x3f8c0', 'sub_3F8C0']
['0xd2774', '0x814ec', b'wlg_cgi_get_wep_status', '0x3f908', 'sub_3F908']
['0xd274c', '0x8147f', b'wlg_cgi_get_defaultkey', '0x3f944', 'sub_3F944']
['0xd2764', '0x814c2', b'wlg_cgi_get_keylen', '0x3f9d0', 'sub_3F9D0']
['0xd275c', '0x814af', b'wlg_cgi_get_keyval', '0x3fa9c', 'sub_3FA9C']
['0xd2714', '0x813fb', b'wlg_cgi_get_ssid', '0x3fc20', 'sub_3FC20']
['0xd2724', '0x8141f', b'wlg_cgi_get_band', '0x3fd20', 'sub_3FD20']
['0xd272c', '0x81430', b'wlg_cgi_get_page', '0x3fd6c', 'sub_3FD6C']
['0xd2734', '0x81441', b'wlg_cgi_get_channel', '0x3fea0', 'sub_3FEA0']
['0xd27c4', '0x815d0', b'wlg_cgi_get_device_table', '0x3ff2c', 'sub_3FF2C']
['0xd27cc', '0x815e9', b'wlg_cgi_get_acl_table', '0x4030c', 'sub_4030C']
['0xd277c', '0x81503', b'wlg_cgi_get_acl_status', '0x40324', 'sub_40324']
['0xd27dc', '0x81613', b'wlg_cgi_get_apstate', '0x4036c', 'sub_4036C']
['0xd27e4', '0x81627', b'wlg_cgi_get_bcaststate', '0x403ec', 'sub_403EC']
['0xd27d4', '0x815ff', b'wlg_cgi_get_country', '0x4048c', 'sub_4048C']
['0xd27ec', '0x8163e', b'wlg_cgi_get_chstr', '0x40630', 'sub_40630']
['0xd2754', '0x81496', b'wlg_cgi_get_temp_setting', '0x40c44', 'sub_40C44']
['0xd276c', '0x814d5', b'wlg_cgi_get_passphrase', '0x40d80', 'sub_40D80']
['0xd279c', '0x81559', b'wlg_cgi_get_groupkey_intv', '0x40e64', 'sub_40E64']
['0xd27a4', '0x81573', b'wlg_cgi_get_radius_port', '0x40ef4', 'sub_40EF4']
['0xd27ac', '0x8158b', b'wlg_cgi_get_raduis_ss', '0x40f84', 'sub_40F84']
['0xd278c', '0x8153a', b'wlg_cgi_get_psk', '0x41014', 'sub_41014']
['0xd2794', '0x8154a', b'psk_status_get', '0x41158', 'sub_41158']
['0xd27b4', '0x815a1', b'psk_5g_status_get', '0x41284', 'sub_41284']
['0xd27fc', '0x81668', b'wlg_cgi_get_frag_threshold', '0x413b0', 'sub_413B0']
['0xd2c6c', '0x8245d', b'Check_Performance_Boost', '0x413f0', 'sub_413F0']
['0xd2804', '0x81683', b'wlg_cgi_get_rts_threshold', '0x4150c', 'sub_4150C']
['0xd30e4', '0x82b73', b'ap_mode.cgi', '0x4154c', 'sub_4154C']
['0xd2e0c', '0x82678', b'wlg_adv.cgi', '0x41b80', 'sub_41B80']
['0xd270c', '0x813e9', b'wlg_cgi_get_param', '0x43444', 'sub_43444']
['0xd2524', '0x80e8a', b'boardid_comment', '0x43b84', 'sub_43B84']
['0xd2814', '0x816b3', b'wlg_cgi_get_sche_table', '0x43e80', 'sub_43E80']
['0xd2f64', '0x828e4', b'wifi_sche.cgi', '0x44928', 'sub_44928']
['0xd2b9c', '0x821f3', b'wlg_cgi_get_5gpresetssid', '0x456d8', 'sub_456D8']
['0xd2ba4', '0x8220c', b'wlg_cgi_get_5gpresetpassphrase', '0x45730', 'sub_45730']
['0xd2b5c', '0x820eb', b'newgui_get_wifi_icon', '0x457b0', 'sub_457B0']
['0xd281c', '0x816ca', b'wlg_cgi_get_wifionoff_status', '0x45828', 'sub_45828']
['0xd2c74', '0x82475', b'wlg_cgi_get_operation_mode', '0x45898', 'sub_45898']
['0xd2834', '0x81705', b'ver_get_pgbarcount', '0x45ce4', 'sub_45CE4']
['0xd283c', '0x81718', b'ver_cgi_get_release_notes', '0x45de0', 'sub_45DE0']
['0xd282c', '0x816f3', b'ver_cgi_get_param', '0x47118', 'sub_47118']
['0xd2e14', '0x82684', b'ver_sel.cgi', '0x473b4', 'sub_473B4']
['0xd2e2c', '0x826b4', b'ver_result.cgi', '0x47634', 'sub_47634']
['0xd2e34', '0x826c3', b'ver_download.cgi', '0x4768c', 'sub_4768C']
['0xd2e3c', '0x826d4', b'ver_write.cgi', '0x47a20', 'sub_47A20']
['0xd2e24', '0x826a6', b'ver_check.cgi', '0x47cf8', 'sub_47CF8']
['0xd2c64', '0x82441', b'ver_cgi_get_pnpx_fw_upgrade', '0x49340', 'sub_49340']
['0xd287c', '0x817ca', b'ef_get_device_id', '0x49764', 'sub_49764']
['0xd2884', '0x817db', b'ef_get_hw_ver', '0x49780', 'sub_49780']
['0xd2894', '0x817f7', b'ef_get_wireless_security', '0x4980c', 'sub_4980C']
['0xd288c', '0x817e9', b'ef_get_sw_ver', '0x498dc', 'sub_498DC']
['0xd2bfc', '0x82328', b'ef_get_newfirmware_version', '0x49924', 'sub_49924']
['0xd2d74', '0x825c9', b'upnp.cgi', '0x4999c', 'sub_4999C']
['0xd2644', '0x811bf', b'upnp_cgi_get_param', '0x49b64', 'sub_49B64']
['0xd2eac', '0x82763', b'wps_button.cgi', '0x4a0d0', 'sub_4A0D0']
['0xd2eb4', '0x82772', b'wps_pin.cgi', '0x4a278', 'sub_4A278']
['0xd2ebc', '0x8277e', b'wps_status.cgi', '0x4a5d4', 'sub_4A5D4']
['0xd289c', '0x81810', b'wps_cgi_get_param', '0x4ac30', 'sub_4AC30']
['0xd28f4', '0x818f0', b'wds_cgi_get_param', '0x4be88', 'sub_4BE88']
['0xd2ec4', '0x8278d', b'wds.cgi', '0x4c3d0', 'sub_4C3D0']
['0xd28ac', '0x81838', b'fw_get_version', '0x4ce94', 'sub_4CE94']
['0xd28b4', '0x81847', b'fw_get_region', '0x4cec0', 'sub_4CEC0']
['0xd28bc', '0x81855', b'fw_get_reg_tag', '0x4d01c', 'sub_4D01C']
['0xd28c4', '0x81864', b'fw_get_model', '0x4d16c', 'sub_4D16C']
['0xd28cc', '0x81871', b'fw_get_internet_status', '0x4d1d4', 'sub_4D1D4']
['0xd28e4', '0x818b9', b'fw_get_ReadyShare_supported_level', '0x4d2a0', 'sub_4D2A0']
['0xd28dc', '0x818a0', b'fwCheckCgi_getPnpxStatus', '0x4d300', 'sub_4D300']
['0xd2ecc', '0x82795', b'fw_check.cgi', '0x4d438', 'sub_4D438']
['0xd28ec', '0x818db', b'fw_check_get_opendns', '0x4da94', 'sub_4DA94']
['0xd2b64', '0x82100', b'ver_cgi_get_new_fw_available', '0x4dab0', 'sub_4DAB0']
['0xd28fc', '0x81902', b'qos_cgi_get_qos_table', '0x4f154', 'sub_4F154']
['0xd2bcc', '0x8229d', b'qos_cgi_gui_get_qos_table', '0x4f490', 'sub_4F490']
['0xd2f3c', '0x8287b', b'bandwidth_check.cgi', '0x4f9b0', 'sub_4F9B0']
['0xd2f1c', '0x82845', b'qos_main.cgi', '0x4fd40', 'sub_4FD40']
['0xd2f34', '0x8286a', b'qos_rule_tab.cgi', '0x50460', 'sub_50460']
['0xd2904', '0x81918', b'qos_cgi_get_apps_options', '0x50748', 'sub_50748']
['0xd290c', '0x81931', b'qos_cgi_get_lan_port_options', '0x50850', 'sub_50850']
['0xd2914', '0x8194e', b'qos_cgi_get_mac_table', '0x508c4', 'sub_508C4']
['0xd291c', '0x81964', b'qos_cgi_get_mac_section', '0x50c6c', 'sub_50C6C']
['0xd2924', '0x8197c', b'qos_cgi_get_mac_buttons', '0x50cf4', 'sub_50CF4']
['0xd292c', '0x81994', b'qos_cgi_get_port_range_section', '0x50dfc', 'sub_50DFC']
['0xd2934', '0x819b3', b'qos_cgi_param_get', '0x50ed0', 'sub_50ED0']
['0xd2f24', '0x82852', b'qos_serv.cgi', '0x513e4', 'sub_513E4']
['0xd2f2c', '0x8285f', b'qos_bw.cgi', '0x5211c', 'sub_5211C']
['0xd2f6c', '0x828f2', b'wifi.cgi', '0x52288', 'sub_52288']
['0xd2f74', '0x828fb', b'wifichset.cgi', '0x52528', 'sub_52528']
['0xd3074', '0x82ac9', b'newgui_adv_home.cgi', '0x525ac', 'sub_525AC']
['0xd30c4', '0x82b29', b'congratulations.cgi', '0x52754', 'sub_52754']
['0xd3014', '0x82a37', b'geniewan.cgi', '0x529dc', 'sub_529DC']
['0xd2ffc', '0x82a09', b'geniestart.cgi', '0x5302c', 'sub_5302C']
['0xd3004', '0x82a18', b'geniereset.cgi', '0x53044', 'sub_53044']
['0xd301c', '0x6cff1', b'genieping.cgi', '0x5305c', 'sub_5305C']
['0xd3024', '0x82a44', b'genieping2.cgi', '0x531c8', 'sub_531C8']
['0xd302c', '0x82a53', b'genieping3.cgi', '0x532e0', 'sub_532E0']
['0xd300c', '0x82a27', b'geniemanual.cgi', '0x5344c', 'sub_5344C']
['0xd2a8c', '0x81dbe', b'cdl_disable_hijack', '0x534fc', 'sub_534FC']
['0xd2a94', '0x81dd1', b'cdl_load_wireless', '0x53518', 'sub_53518']
['0xd307c', '0x82add', b'genieDisableLanChanged.cgi', '0x53560', 'sub_53560']
['0xd2b7c', '0x82160', b'genie_show_congratulation_title', '0x535e8', 'sub_535E8']
['0xd2b74', '0x8213d', b'genie_get_5g_wireless_security_key', '0x53860', 'sub_53860']
['0xd2b6c', '0x8211d', b'genie_get_wireless_security_key', '0x538bc', 'sub_538BC']
['0xd2b8c', '0x821a8', b'genie_get_congratulations_page_style', '0x53a44', 'sub_53A44']
['0xd2b84', '0x82180', b'genie_get_congratulations_page_style_5g', '0x53aa8', 'sub_53AA8']
['0xd2b94', '0x821cd', b'genie_get_congratulations_page_style2', '0x53b0c', 'sub_53B0C']
['0xd2bac', '0x8222b', b'genie_cgi_set_if_show_firmware_ver', '0x53b9c', 'sub_53B9C']
['0xd2bc4', '0x82281', b'genie_cgi_show_firmware_ver', '0x53bc8', 'sub_53BC8']
['0xd2bb4', '0x8224e', b'genie_cgi_get_firmware_ver', '0x53c64', 'sub_53C64']
['0xd2bbc', '0x82269', b'genie_cgi_get_frame_src', '0x53cc4', 'sub_53CC4']
['0xd2bdc', '0x822c7', b'genie_cgi_get_serial', '0x53d5c', 'sub_53D5C']
['0xd2be4', '0x822dc', b'genie_cgi_get_font', '0x53d90', 'sub_53D90']
['0xd2c24', '0x82391', b'genie_cgi_set_genie', '0x53dd4', 'sub_53DD4']
['0xd2c2c', '0x823a5', b'genie_cgi_get_genie', '0x53e08', 'sub_53E08']
['0xd2a9c', '0x81de3', b'gui_cgi_get_Internet_state', '0x53e90', 'sub_53E90']
['0xd2aa4', '0x81dfe', b'gui_cgi_get_Internet_status_param', '0x53ffc', 'sub_53FFC']
['0xd2ab4', '0x81e45', b'gui_cgi_get_Internet_result', '0x540a8', 'sub_540A8']
['0xd2aac', '0x81e20', b'gui_cgi_get_Internet_condition_param', '0x54120', 'sub_54120']
['0xd2abc', '0x81e61', b'gui_cgi_get_Wireless_radio_state', '0x54164', 'sub_54164']
['0xd2ac4', '0x81e82', b'gui_cgi_get_Wireless_security_state', '0x54270', 'sub_54270']
['0xd2acc', '0x81ea6', b'gui_cgi_get_Wireless_status_param', '0x54378', 'sub_54378']
['0xd2ad4', '0x81ec8', b'gui_cgi_get_AttachedDevices_state', '0x553fc', 'sub_553FC']
['0xd2adc', '0x81eea', b'gui_cgi_get_AttachedDevices_condition_param', '0x555e4', 'sub_555E4']
['0xd2ae4', '0x81f16', b'gui_cgi_get_ParentalControls_state', '0x55674', 'sub_55674']
['0xd2aec', '0x81f39', b'gui_cgi_get_ReadyShare_state', '0x55720', 'sub_55720']
['0xd2af4', '0x81f56', b'gui_cgi_get_GuestNetwork_state', '0x55860', 'sub_55860']
['0xd2afc', '0x81f75', b'gui_cgi_get_GuestNetwork_status_param', '0x559ac', 'sub_559AC']
['0xd2c0c', '0x8235b', b'gui_get_wps_mode', '0x563ec', 'sub_563EC']
['0xd2c14', '0x8236c', b'gui_get_repeater_mode', '0x56438', 'sub_56438']
['0xd30d4', '0x82b4c', b'autoblock.cgi', '0x565bc', 'sub_565BC']
['0xd2c34', '0x823b9', b'gui_get_ap_mode', '0x565f0', 'sub_565F0']
['0xd2c3c', '0x823c9', b'gui_get_repeater_or_ap_mode', '0x56704', 'sub_56704']
['0xd2c44', '0x823e5', b'gui_get_station_mode', '0x56898', 'sub_56898']
['0xd2c7c', '0x82490', b'check_smartnetwork_support', '0x5696c', 'sub_5696C']
['0xd2c84', '0x824ab', b'check_smartnetwork_enable', '0x56988', 'sub_56988']
['0xd30cc', '0x82b3d', b'upnp_media.cgi', '0x56b6c', 'sub_56B6C']
['0xd2bf4', '0x8230f', b'upnp_media_cgi_get_param', '0x56d4c', 'sub_56D4C']
['0xd2944', '0x819db', b'tra_init', '0x57354', 'sub_57354']
['0xd294c', '0x819e4', b'tra_supported', '0x5740c', 'sub_5740C']
['0xd2954', '0x819f2', b'tra_stat_get', '0x57428', 'sub_57428']
['0xd295c', '0x819ff', b'tra_get_param', '0x57808', 'sub_57808']
['0xd2f44', '0x8288f', b'traffic.cgi', '0x58414', 'sub_58414']
['0xd2f4c', '0x8289b', b'traffic_status.cgi', '0x58acc', 'sub_58ACC']
['0xd2f54', '0x828ae', b'traffic_important_update.cgi', '0x58ae4', 'sub_58AE4']
['0xd2a5c', '0x81d3e', b'usb_cgi_get_smb_link_style', '0x59948', 'sub_59948']
['0xd2a3c', '0x81cee', b'usb_cgi_get_url', '0x59ed8', 'sub_59ED8']
['0xd2a74', '0x81d87', b'usb_cgi_get_option', '0x5a418', 'sub_5A418']
['0xd2a7c', '0x81d9a', b'usb_cgi_get_info', '0x5a9b8', 'sub_5A9B8']
['0xd2a6c', '0x81d71', b'usb_cgi_get_mount_num', '0x5ae48', 'sub_5AE48']
['0xd2a44', '0x81cfe', b'usb_cgi_get_param', '0x5aed0', 'sub_5AED0']
['0xd2a64', '0x81d59', b'usb_cgi_get_mount_table', '0x5b250', 'sub_5B250']
['0xd2a54', '0x81d22', b'usb_cgi_is_all_admin_folder', '0x5c0c4', 'sub_5C0C4']
['0xd2a4c', '0x81d10', b'usb_cgi_get_table', '0x5c1e0', 'sub_5C1E0']
['0xd2a2c', '0x81cc0', b'usb_cgi_get_dev_table', '0x5d968', 'sub_5D968']
['0xd2f84', '0x82919', b'usb_browse.cgi', '0x5dff4', 'sub_5DFF4']
['0xd2f94', '0x82939', b'usb_adv_main.cgi', '0x5fa3c', 'sub_5FA3C']
['0xd2f9c', '0x8294a', b'usb_basic_main.cgi', '0x5fa9c', 'sub_5FA9C']
['0xd2fac', '0x82969', b'usb_device.cgi', '0x5ffc8', 'sub_5FFC8']
['0xd2f8c', '0x82928', b'usb_settings.cgi', '0x60f1c', 'sub_60F1C']
['0xd2f7c', '0x82909', b'usb_approve.cgi', '0x60f9c', 'sub_60F9C']
['0xd2fb4', '0x82978', b'usb_umount.cgi', '0x61568', 'sub_61568']
['0xd2fa4', '0x8295d', b'usb_adv.cgi', '0x61b0c', 'sub_61B0C']
['0xd298c', '0x81a9d', b'wlg_get_sec_profile_status', '0x62774', 'sub_62774']
['0xd296c', '0x81a29', b'wlg_get_sec_profile_num', '0x62d54', 'sub_62D54']
['0xd2974', '0x81a41', b'wlg_get_sec_profile_enable', '0x62d74', 'sub_62D74']
['0xd297c', '0x81a5c', b'wlg_get_sec_profile_ssid_bc', '0x62e10', 'sub_62E10']
['0xd2984', '0x81a78', b'wlg_get_sec_profile_allow_see_access', '0x62eac', 'sub_62EAC']
['0xd2f5c', '0x828cb', b'wlg_sec_profile_main.cgi', '0x6309c', 'sub_6309C']
['0xd2994', '0x81ab8', b'wlg_get_sec_profile_secutype', '0x64644', 'sub_64644']
['0xd29cc', '0x81b7d', b'wlg_get_sec_profile_authtype', '0x64688', 'sub_64688']
['0xd29d4', '0x81b9a', b'wlg_get_sec_profile_defaultkey', '0x64710', 'sub_64710']
['0xd29dc', '0x81bb9', b'wlg_get_sec_profile_wep_length', '0x64758', 'sub_64758']
['0xd29e4', '0x81bd8', b'wlg_get_sec_profile_keyval', '0x64814', 'sub_64814']
['0xd299c', '0x81ad5', b'wlg_get_sec_profile_ssid', '0x648ec', 'sub_648EC']
['0xd2964', '0x81a0d', b'wlg_get_sec_profile_setting', '0x649b8', 'sub_649B8']
['0xd29c4', '0x81b5e', b'wlg_get_sec_profile_passphrase', '0x64aac', 'sub_64AAC']
['0xd29bc', '0x81b46', b'wlg_get_sec_profile_psk', '0x64b88', 'sub_64B88']
['0xd29a4', '0x81aee', b'wlg_get_sec_profile_psk_status', '0x64d58', 'sub_64D58']
['0xd29ac', '0x81b0d', b'wlg_get_sec_profile_psk_5g_status', '0x64eb0', 'sub_64EB0']
['0xd29b4', '0x81b2f', b'wlg_cgi_get_guest_page', '0x65008', 'sub_65008']
['0xd306c', '0x82aba', b'genie_lang.cgi', '0x65904', 'sub_65904']
['0xd284c', '0x81745', b'lang_cgi_get_ver', '0x67660', 'sub_67660']
['0xd2844', '0x81732', b'lang_cgi_get_param', '0x676b0', 'sub_676B0']
['0xd2e44', '0x826e2', b'lang_lang.cgi', '0x67a8c', 'sub_67A8C']
['0xd2e4c', '0x826f0', b'lang_check.cgi', '0x67b50', 'sub_67B50']
['0xd2e54', '0x826ff', b'lang_result.cgi', '0x68294', 'sub_68294']
['0xd2e5c', '0x8270f', b'lang_download.cgi', '0x6835c', 'sub_6835C']
['0xd2e64', '0x82721', b'lang_write.cgi', '0x68364', 'sub_68364']
['0xd2e74', '0x82730', b'langbrscheck.cgi', '0x6836c', 'sub_6836C']
['0xd2e6c', '0x6d6fe', b'lang_top.cgi', '0x68824', 'sub_68824']
['0xd2bd4', '0x822b7', b'lang_set_target', '0x688f0', 'sub_688F0']
['0xd30ac', '0x82af8', b'lang_settop.cgi', '0x6894c', 'sub_6894C']
['0xd30b4', '0x82b08', b'lang_settop2.cgi', '0x68a1c', 'sub_68A1C']
['0xd30bc', '0x82b19', b'lang_check2.cgi', '0x68aec', 'sub_68AEC']
['0xd2e7c', '0x82741', b'brschagelang.cgi', '0x69298', 'sub_69298']
['0xd2e84', '0x6dea7', b'strtblupgrade.cgi', '0x69398', 'sub_69398']
['0xd2854', '0x81756', b'lang_cgi_get_bk_pic', '0x693b8', 'sub_693B8']
['0xd2e8c', '0x6d6f6', b'sku.cgi', '0x693d4', 'sub_693D4']
['0xd2474', '0x80cb2', b'getstr', '0x6a5c0', 'sub_6A5C0']
['0xd2a1c', '0x81c92', b'debug_cgi_get_param', '0x6ae7c', 'sub_6AE7C']
['0xd2fbc', '0x82987', b'ipv6_disable.cgi', '0x6b084', 'sub_6B084']
['0xd2fc4', '0x82998', b'ipv6_auto.cgi', '0x6b0e0', 'sub_6B0E0']
['0xd2fcc', '0x829a6', b'ipv6_tunnel.cgi', '0x6b2e8', 'sub_6B2E8']
['0xd2fd4', '0x829b6', b'ipv6_passthrough.cgi', '0x6b644', 'sub_6B644']
['0xd2fdc', '0x829cb', b'ipv6_fix.cgi', '0x6b6c0', 'sub_6B6C0']
['0xd2fe4', '0x829d8', b'ipv6_dhcp.cgi', '0x6ba70', 'sub_6BA70']
['0xd2fec', '0x829e6', b'ipv6_pppoe.cgi', '0x6bd14', 'sub_6BD14']
['0xd2ff4', '0x829f5', b'ipv6_autoconfig.cgi', '0x6bff8', 'sub_6BFF8']
['0xd2a84', '0x81dab', b'ipv6_cgi_get_param', '0x6c4c0', 'sub_6C4C0']
table_records
0xd2470 0xd2c8c 125
0xd2c98 0xd30e4 125
```

## SaTC前端参数字符串提取

![](images/Pasted%20image%2020231121095935.png)

## 解析函数提取
基于提取的前端参数字符串识别后端handle函数内的参数提取函数。

![](images/Pasted%20image%2020231121100946.png)

依次寻找字符串位置，然后遍历交叉引用位置，判断是否为函数参数，且函数另一个参数为一个变量，是则视为匹配并保存。同时记录hit的函数名称并统计hit次数，最后根据统计结果再采取策略（如hit次数最高）选择参数解析函数。

1.单纯使用参数字符串作为参数的情况
2.使用参数字符串+一个变量作为参数的情况


## end