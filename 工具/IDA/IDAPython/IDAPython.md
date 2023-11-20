

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

执行结果：
```
[ERROR] error in caller func cf
[['0xe5e4', 'sub_EC40', '0xec40', 'write', '0xec94'], ['0x2d5c4', 'sub_164C8', '0x164c8', '/goform', '0x15b98'], ['0x2d640', 'sub_164C8', '0x164c8', '/', '0x2d698'], ['0x2d640', 'sub_164C8', '0x164c8', '/', '0x2d698'], ['0x2d5ec', 'sub_164C8', '0x164c8', '/cgi-bin', '0x38e00'], ['0x3fd84', 'sub_EC40', '0xec40', 'aspGetCharset', '0x4140c'], ['0x403c0', 'sub_EC40', '0xec40', 'mNatGetStatic', '0x4146c'], ['0x403dc', 'sub_EC40', '0xec40', 'asp_error_message', '0x418a4'], ['0x403f8', 'sub_EC40', '0xec40', 'asp_error_redirect_url', '0x41904'], ['0x40414', 'sub_EC40', '0xec40', 'mGetIPRate', '0x41964'], ['0x40bd8', 'sub_15D0C', '0x15d0c', 'MfgTest', '0x41d78'], ['0x41180', 'sub_EC40', '0xec40', 'getcfm', '0x41f34'], ['0x4119c', 'sub_15D0C', '0x15d0c', 'setcfm', '0x41ff8'], ['0x41244', 'sub_EC40', '0xec40', 'getifnlist', '0x42590'], ['0x40bbc', 'sub_15D0C', '0x15d0c', 'WriteFacMac', '0x42794'], ['0x3fc50', 'sub_15D0C', '0x15d0c', 'updateUrlLog', '0x4292c'], ['0x41404', 'sub_15D0C', '0x15d0c', 'getRebootStatus', '0x42b0c'], ['0x41404', 'sub_15D0C', '0x15d0c', 'getRebootStatus', '0x42b0c'], ['0x40708', 'sub_15D0C', '0x15d0c', 'SysToolReboot', '0x42c98'], ['0x411d4', 'sub_EC40', '0xec40', 'getModeShow', '0x42f3c'], ['0x411b8', 'sub_EC40', '0xec40', 'getfilterMaxNum', '0x43d34'], ['0x3fc34', 'sub_EC40', '0xec40', 'aspTendaGetStatus', '0x44078'], ['0x3fc18', 'sub_EC40', '0xec40', 'TendaGetLongString', '0x49c1c'], ['0x40724', 'sub_15D0C', '0x15d0c', 'telnet', '0x4aef0'], ['0x41228', 'sub_15D0C', '0x15d0c', 'QuickIndex', '0x4b4e0'], ['0x3fda0', 'sub_15D0C', '0x15d0c', 'WizardHandle', '0x4b9b4'], ['0x3ff60', 'sub_15D0C', '0x15d0c', 'AdvSetLanip', '0x4d3dc'], ['0x3ff44', 'sub_15D0C', '0x15d0c', 'AdvGetLanIp', '0x4db18'], ['0x3fca4', 'sub_15D0C', '0x15d0c', 'GetSysInfo', '0x4ea58'], ['0x3fc88', 'sub_15D0C', '0x15d0c', 'GetWanStatus', '0x4f084'], ['0x3fc6c', 'sub_15D0C', '0x15d0c', 'SysStatusHandle', '0x4f2b0'], ['0x3fcc0', 'sub_15D0C', '0x15d0c', 'GetWanStatistic', '0x4f484'], ['0x3fcdc', 'sub_15D0C', '0x15d0c', 'GetAllWanInfo', '0x4f764'], ['0x3fcf8', 'sub_15D0C', '0x15d0c', 'GetWanNum', '0x4fb14'], ['0x3fd14', 'sub_EC40', '0xec40', 'aspGetWanNum', '0x4fb78'], ['0x4120c', 'sub_EC40', '0xec40', 'getMaxNatNum', '0x4fbdc'], ['0x3fd30', 'sub_15D0C', '0x15d0c', 'getPortStatus', '0x4fc54'], ['0x3fd4c', 'sub_15D0C', '0x15d0c', 'GetSystemStatus', '0x51130'], ['0x405b8', 'sub_15D0C', '0x15d0c', 'setBlackRule', '0x54670'], ['0x405d4', 'sub_15D0C', '0x15d0c', 'delBlackRule', '0x55218'], ['0x405f0', 'sub_15D0C', '0x15d0c', 'getBlackRuleList', '0x555d8'], ['0x3fd68', 'sub_15D0C', '0x15d0c', 'GetRouterStatus', '0x559b8'], ['0x40238', 'sub_15D0C', '0x15d0c', 'getOnlineList', '0x56974'], ['0x404f4', 'sub_15D0C', '0x15d0c', 'GetDeviceDetail', '0x57438'], ['0x4052c', 'sub_15D0C', '0x15d0c', 'SetOnlineDevName', '0x581a0'], ['0x40510', 'sub_15D0C', '0x15d0c', 'SetClientState', '0x583c8'], ['0x40564', 'sub_15D0C', '0x15d0c', 'SetSpeedWan', '0x58738'], ['0x413e8', 'sub_15D0C', '0x15d0c', 'GetSysStatus', '0x58a88'], ['0x40254', 'sub_15D0C', '0x15d0c', 'GetAdvanceStatus', '0x5912c'], ['0x404bc', 'sub_15D0C', '0x15d0c', 'SetNetControlList', '0x59748'], ['0x404d8', 'sub_15D0C', '0x15d0c', 'GetNetControlList', '0x5998c'], ['0x3fdbc', 'sub_15D0C', '0x15d0c', 'fast_setting_get', '0x5a4e4'], ['0x3fdd8', 'sub_15D0C', '0x15d0c', 'fast_setting_pppoe_get', '0x5a8e4'], ['0x3fe2c', 'sub_15D0C', '0x15d0c', 'getWanConnectStatus', '0x5ab00'], ['0x3fe10', 'sub_15D0C', '0x15d0c', 'fast_setting_pppoe_set', '0x5ae48'], ['0x3fdf4', 'sub_15D0C', '0x15d0c', 'fast_setting_wifi_set', '0x5b010'], ['0x3fe48', 'sub_15D0C', '0x15d0c', 'getProduct', '0x5b990'], ['0x3fe64', 'sub_15D0C', '0x15d0c', 'usb_get', '0x5bc4c'], ['0x40b84', 'sub_15D0C', '0x15d0c', 'ate', '0x5fd00'], ['0x3ff7c', 'sub_15D0C', '0x15d0c', 'SetWebIpAccess', '0x5fd54'], ['0x3ff98', 'sub_15D0C', '0x15d0c', 'WanPolicy', '0x5feb4'], ['0x3ff0c', 'sub_15D0C', '0x15d0c', 'AdvSetMTU', '0x60768'], ['0x3ff28', 'sub_15D0C', '0x15d0c', 'AdvGetMTU', '0x60938'], ['0x40040', 'sub_15D0C', '0x15d0c', 'WanParameterSetting', '0x60b34'], ['0x4005c', 'sub_15D0C', '0x15d0c', 'getWanParameters', '0x61ba8'], ['0x40078', 'sub_15D0C', '0x15d0c', 'wanNumSet', '0x64a3c'], ['0x40094', 'sub_15D0C', '0x15d0c', 'getAdvanceStatus', '0x64ba4'], ['0x3fef0', 'sub_15D0C', '0x15d0c', 'AdvSetMacMtuWan', '0x65800'], ['0x3fed4', 'sub_15D0C', '0x15d0c', 'AdvGetMacMtuWan', '0x65dc8'], ['0x3ffb4', 'sub_15D0C', '0x15d0c', 'SetRemoteWebCfg', '0x66268'], ['0x3ffd0', 'sub_15D0C', '0x15d0c', 'GetRemoteWebCfg', '0x664a4'], ['0x402a8', 'sub_15D0C', '0x15d0c', 'SetDMZCfg', '0x66750'], ['0x402c4', 'sub_15D0C', '0x15d0c', 'GetDMZCfg', '0x66948'], ['0x3ffec', 'sub_15D0C', '0x15d0c', 'WanPortParam', '0x66c74'], ['0x40008', 'sub_15D0C', '0x15d0c', 'AdvSetMacClone', '0x66e78'], ['0x40024', 'sub_15D0C', '0x15d0c', 'AdvGetMacClone', '0x67274'], ['0x40270', 'sub_15D0C', '0x15d0c', 'SetVirtualServerCfg', '0x683f8'], ['0x4028c', 'sub_15D0C', '0x15d0c', 'GetVirtualServerCfg', '0x68518'], ['0x40318', 'sub_15D0C', '0x15d0c', 'NatStaticSetting', '0x68850'], ['0x40484', 'sub_EC40', '0xec40', 'NatSet', '0x689f8'], ['0x40468', 'sub_15D0C', '0x15d0c', 'AdvSetNat', '0x68abc'], ['0x40334', 'sub_15D0C', '0x15d0c', 'SetDDNSCfg', '0x68b88'], ['0x40350', 'sub_15D0C', '0x15d0c', 'GetDDNSCfg', '0x692b4'], ['0x4036c', 'sub_EC40', '0xec40', 'mGetRouteTable', '0x69614'], ['0x40388', 'sub_15D0C', '0x15d0c', 'RouteStatic', '0x697b0'], ['0x403a4', 'sub_15D0C', '0x15d0c', 'addressNat', '0x69c6c'], ['0x406b4', 'sub_15D0C', '0x15d0c', 'SysToolSysLog', '0x69e00'], ['0x40698', 'sub_15D0C', '0x15d0c', 'GetSySLogCfg', '0x69e5c'], ['0x406d0', 'sub_15D0C', '0x15d0c', 'LogsSetting', '0x6a1b8'], ['0x40740', 'sub_15D0C', '0x15d0c', 'SysToolRestoreSet', '0x6a334'], ['0x3fe80', 'sub_15D0C', '0x15d0c', 'SysToolpassword', '0x6a388'], ['0x4075c', 'sub_15D0C', '0x15d0c', 'SysToolChangePwd', '0x6a45c'], ['0x40778', 'sub_15D0C', '0x15d0c', 'SysToolBaseUser', '0x6a798'], ['0x40548', 'sub_15D0C', '0x15d0c', 'GetSystemSet', '0x6a990'], ['0x40794', 'sub_15D0C', '0x15d0c', 'SysToolGetUpgrade', '0x6aaa8'], ['0x407b0', 'sub_15D0C', '0x15d0c', 'SysToolSetUpgrade', '0x6ab9c'], ['0x40ba0', 'sub_15D0C', '0x15d0c', 'exeCommand', '0x6b558'], ['0x40644', 'sub_15D0C', '0x15d0c', 'initAutoQos', '0x6d8cc'], ['0x40660', 'sub_15D0C', '0x15d0c', 'saveAutoQos', '0x6db98'], ['0x4067c', 'sub_15D0C', '0x15d0c', 'getQosSpeed', '0x6dd54'], ['0x40158', 'sub_15D0C', '0x15d0c', 'GetParentControlInfo', '0x70fcc'], ['0x40174', 'sub_15D0C', '0x15d0c', 'saveParentControlInfo', '0x7304c'], ['0x40580', 'sub_15D0C', '0x15d0c', 'getParentalRuleList', '0x74054'], ['0x4059c', 'sub_15D0C', '0x15d0c', 'delParentalRule', '0x744fc'], ['0x404a0', 'sub_15D0C', '0x15d0c', 'GetParentCtrlList', '0x74e94'], ['0x402fc', 'sub_15D0C', '0x15d0c', 'SetUpnpCfg', '0x756fc'], ['0x402e0', 'sub_15D0C', '0x15d0c', 'GetUpnpCfg', '0x75828'], ['0x401ac', 'sub_15D0C', '0x15d0c', 'DhcpSetSer', '0x75af8'], ['0x40190', 'sub_15D0C', '0x15d0c', 'GetDhcpServer', '0x760d8'], ['0x401e4', 'sub_15D0C', '0x15d0c', 'DhcpListClient', '0x76484'], ['0x401c8', 'sub_EC40', '0xec40', 'TendaGetDhcpClients', '0x766dc'], ['0x4021c', 'sub_EC40', '0xec40', 'TendaGetDhcpClients', '0x766dc'], ['0x40200', 'sub_15D0C', '0x15d0c', 'ajaxTendaGetDhcpClients', '0x77008'], ['0x411f0', 'sub_15D0C', '0x15d0c', 'ajaxTendaGetGuestDhcpClients', '0x77404'], ['0x406ec', 'sub_15D0C', '0x15d0c', 'SysToolTime', '0x7781c'], ['0x41298', 'sub_15D0C', '0x15d0c', 'SetSysTimeCfg', '0x77cf0'], ['0x412b4', 'sub_15D0C', '0x15d0c', 'GetSysTimeCfg', '0x7827c'], ['0x40104', 'sub_15D0C', '0x15d0c', 'openSchedWifi', '0x78b74'], ['0x400e8', 'sub_15D0C', '0x15d0c', 'initSchedWifi', '0x790fc'], ['0x4013c', 'sub_15D0C', '0x15d0c', 'SetLEDCfg', '0x79948'], ['0x40120', 'sub_15D0C', '0x15d0c', 'GetLEDCfg', '0x79ca0'], ['0x4044c', 'sub_15D0C', '0x15d0c', 'BulletinSet', '0x7a060'], ['0x40430', 'sub_15D0C', '0x15d0c', 'AdvSetPortVlan', '0x7a28c'], ['0x41164', 'sub_EC40', '0xec40', 'GetPortShow', '0x7a318'], ['0x407cc', 'sub_15D0C', '0x15d0c', 'WifiMultiSsid', '0x7ae18'], ['0x407e8', 'sub_15D0C', '0x15d0c', 'WifiBasicGet', '0x7b348'], ['0x40804', 'sub_15D0C', '0x15d0c', 'WifiBasicSet', '0x7c430'], ['0x40820', 'sub_15D0C', '0x15d0c', 'WifiApScan', '0x7d828'], ['0x4083c', 'sub_15D0C', '0x15d0c', 'WifiClientList', '0x7f078'], ['0x40858', 'sub_15D0C', '0x15d0c', 'WifiClientListAll', '0x7f318'], ['0x408ac', 'sub_15D0C', '0x15d0c', 'initWifiMacFilter', '0x7f57c'], ['0x408c8', 'sub_15D0C', '0x15d0c', 'addWifiMacFilter', '0x7fe00'], ['0x408e4', 'sub_15D0C', '0x15d0c', 'delWifiMacFilter', '0x80238'], ['0x40874', 'sub_15D0C', '0x15d0c', 'WifiMacFilterGet', '0x80670'], ['0x40890', 'sub_15D0C', '0x15d0c', 'WifiMacFilterSet', '0x80c08'], ['0x40900', 'sub_15D0C', '0x15d0c', 'WifiRadioGet', '0x811a4'], ['0x4091c', 'sub_15D0C', '0x15d0c', 'WifiRadioSet', '0x8160c'], ['0x40954', 'sub_15D0C', '0x15d0c', 'WifiPowerSet', '0x82654'], ['0x40938', 'sub_15D0C', '0x15d0c', 'WifiPowerGet', '0x82ce4'], ['0x40970', 'sub_15D0C', '0x15d0c', 'WifiStatistic', '0x82e54'], ['0x4098c', 'sub_15D0C', '0x15d0c', 'WifiStatisticClear', '0x83538'], ['0x409a8', 'sub_15D0C', '0x15d0c', 'WifiDhcpGuestGet', '0x835b0'], ['0x409c4', 'sub_15D0C', '0x15d0c', 'WifiDhcpGuestLists', '0x837d8'], ['0x409e0', 'sub_15D0C', '0x15d0c', 'WifiDhcpGuestSet', '0x83c70'], ['0x409fc', 'sub_15D0C', '0x15d0c', 'WifiStatus', '0x8403c'], ['0x40a6c', 'sub_15D0C', '0x15d0c', 'WifiConfigGet', '0x848f0'], ['0x40a34', 'sub_15D0C', '0x15d0c', 'WifiWpsStart', '0x84a28'], ['0x40a50', 'sub_15D0C', '0x15d0c', 'WifiWpsOOB', '0x85e34'], ['0x40aa4', 'sub_15D0C', '0x15d0c', 'WifiWpsSet', '0x86784'], ['0x40ac0', 'sub_15D0C', '0x15d0c', 'WifiWpsStart', '0x86958'], ['0x40a88', 'sub_15D0C', '0x15d0c', 'WifiWpsGet', '0x86a90'], ['0x41308', 'sub_15D0C', '0x15d0c', 'WifiGuestSet', '0x8a1e0'], ['0x41324', 'sub_15D0C', '0x15d0c', 'WifiGuestGet', '0x8a5c4'], ['0x412d0', 'sub_15D0C', '0x15d0c', 'WifiExtraSet', '0x8b078'], ['0x412ec', 'sub_15D0C', '0x15d0c', 'WifiExtraGet', '0x8cd70'], ['0x41340', 'sub_15D0C', '0x15d0c', 'GetWrlStatus', '0x8dd10'], ['0x40adc', 'sub_15D0C', '0x15d0c', 'SetPrinterCfg', '0x8e540'], ['0x40af8', 'sub_15D0C', '0x15d0c', 'GetPrinterCfg', '0x8e66c'], ['0x40b14', 'sub_15D0C', '0x15d0c', 'SetSambaCfg', '0x8e720'], ['0x40b30', 'sub_15D0C', '0x15d0c', 'GetSambaCfg', '0x8ea40'], ['0x3fe9c', 'sub_15D0C', '0x15d0c', 'cloud', '0x95114'], ['0x3feb8', 'sub_15D0C', '0x15d0c', 'onlineupgrade', '0x95cb8'], ['0x40a18', 'sub_15D0C', '0x15d0c', 'getAliWifiScheduled', '0x960a0'], ['0x4060c', 'sub_15D0C', '0x15d0c', 'SetIPTVCfg', '0x9683c'], ['0x40628', 'sub_15D0C', '0x15d0c', 'GetIPTVCfg', '0x96cdc'], ['0x40b68', 'sub_15D0C', '0x15d0c', 'GetDlnaCfg', '0x9723c'], ['0x40b4c', 'sub_15D0C', '0x15d0c', 'SetDlnaCfg', '0x9735c'], ['0x41260', 'sub_15D0C', '0x15d0c', 'SetSysAutoRebbotCfg', '0x9764c'], ['0x4127c', 'sub_15D0C', '0x15d0c', 'GetSysAutoRebbotCfg', '0x977e0'], ['0x400b0', 'sub_15D0C', '0x15d0c', 'PowerSaveGet', '0x97ce0'], ['0x400cc', 'sub_15D0C', '0x15d0c', 'PowerSaveSet', '0x984d8'], ['0x4135c', 'sub_15D0C', '0x15d0c', 'SetPptpServerCfg', '0x9b638'], ['0x41378', 'sub_15D0C', '0x15d0c', 'GetPptpServerCfg', '0x9c884'], ['0x41394', 'sub_15D0C', '0x15d0c', 'SetPptpClientCfg', '0x9d34c'], ['0x413b0', 'sub_15D0C', '0x15d0c', 'GetPptpClientCfg', '0x9dadc'], ['0x413cc', 'sub_15D0C', '0x15d0c', 'GetVpnStatus', '0x9e564']]
[('sub_15D0C', 153), ('sub_EC40', 19), ('sub_164C8', 4)]
```

