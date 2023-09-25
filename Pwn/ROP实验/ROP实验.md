## 任意写
向任意内存地址rw写入内容"/bin/sh"，然后调用sys。

需要寻找往内存中写入数据的gadget
```
ROPgadget --binary dhcp.bin --only "mov|ret"
ROPgadget --binary dhcp.bin | grep -v "jmp" | grep "mov"
```

调用sys
```
ROPgadget --binary dhcp.bin --only "pop|ret" | grep "rdi"
```

## evecve调用
调用execve(”/bin/sh”, 0, 0)。需要设置
`rdi`:"/bin/sh"地址
`rsi`:0
`rdx`:0
`eax`:0x3b




## 可控参数检查

