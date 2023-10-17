
获取地址对象
```python
addr_factory = currentProgram.getAddressFactory()
refaddr = addr_factory.getAddress('0x2506c')
```
程序最小最大地址
```python
curAddr = currentProgram.minAddress
end = currentProgram.maxAddress
```

获取交叉引用
```
for ref in getReferencesTo(curAddr):
	print(ref)
```

获取包含某个地址的函数
```
caller = getFunctionContaining(ref.fromAddress)
```



寻找字符串，获取字节数据，增加当前地址
```
curAddr = find(curAddr, target)
getByte(curAddr.add(len(target)))
curAddr = curAddr.add(1)
```