```python
import FIDL.decompiler_utils as du
import idautils

dangerFuncList = ['strcpy', 'strncpy', 'memcpy', 'sscanf', 'sprintf']
skipFuncList = ['va_start', 'va_arg']
pending = set()
safeFuncs = set()
callMap = {}

# 获取text段地址空间
for seg in idautils.Segments():
    if SegName(seg) == ".text":
        text_start = SegStart(seg)
        text_end = SegEnd(seg)
    if SegName(seg) == ".plt":
        plt_start = SegStart(seg)
        plt_end = SegEnd(seg)
        
print(hex(plt_start), hex(plt_end))

def getFuncCalls(callMap, funcAddr):
    if funcAddr in callMap:
        return
    callees = {}
    try:
        cf = du.controlFlowinator(ea=int(funcAddr, 16), fast=False)
    except Exception as ex:
        print(ex)
        return
    for call in cf.calls:
        if call.ea != idc.BADADDR and call.call_ea != idc.BADADDR:
            callees[hex(call.ea)] = hex(call.call_ea)
            if hex(call.call_ea) not in callees and (call.call_ea > plt_end or call.call_ea < plt_start):
                pending.add(hex(call.call_ea))
    callMap[funcAddr] = callees

def printPath(path):
    for item in path:
        item_int = int(item[1], 16)
        if item_int < text_start or item_int >= text_end:
            continue
        if item[1] not in funcCount:
            funcCount[item[1]] = 1
        else:
            funcCount[item[1]] += 1
    print(path)

def dfs(funcAddrStr, path, start=None):
    if funcAddrStr in avoidList:
        return False
    funcAddr = int(funcAddrStr, 16)
    if ida_funcs.get_func_name(funcAddr) in dangerFuncList:
        printPath(path)
        return True
    vulnerable = False
    if funcAddr < text_start or funcAddr >= text_end:
        return False
    for addr, callee in sorted(callMap[funcAddrStr].items()):
        if start is not None and int(addr, 16) < start:
            continue
        if callee in [x[1] for x in path] + [startFunc] or callee in safeFuncs:
            continue
        vulnerable = dfs(callee, path + [(addr, callee)]) or vulnerable
    if not vulnerable and funcAddrStr != startFunc:
        safeFuncs.add(funcAddrStr)
    return vulnerable

'''
    func_addr = idc.get_name_ea(idc.BADADDR, danger_func_name)
        if func_addr != idc.BADADDR:
            danger_func_addr_list.append(func_addr)    
'''

startFunc = hex(0x96004)
funcAddr = 0x96004
start = 0x960C8

avoidList = ['0x9ccbc']
funcCount = {}

pending.add(hex(funcAddr))
while len(pending):
    getFuncCalls(callMap, pending.pop())

#print(callMap)
dfs(hex(funcAddr), [], start)
#print(ida_funcs.get_func_name(0xF938))
print(sorted(funcCount.items(), key=lambda x: x[1], reverse=True))

```
