## 任意写
向任意内存地址rw写入内容"/bin/sh"，然后调用sys。

需要寻找往内存中写入数据的gadget
```
ROPgadget --binary dhcpd.bin --only "mov|ret"
ROPgadget --binary dhcpd.bin | grep -v "jmp" | grep "mov"
```

调用sys
```
ROPgadget --binary dhcpd.bin --only "pop|ret" | grep "rdi"
```

## evecve调用
调用execve(”/bin/sh”, 0, 0)。需要设置
`rdi`:"/bin/sh"地址
`rsi`:0
`rdx`:0
`rax`:0x3b

```
ROPgadget --binary dhcpd.bin --only "pop|ret" | grep "rsi"
ROPgadget --binary dhcpd.bin --only "pop|ret" | grep "rdx"
ROPgadget --binary dhcpd.bin --only "mov|pop|ret" | grep "eax"
ROPgadget --binary dhcpd.bin | grep "syscall"
```


## 可控参数检查
rdi, rsi, rdx, rcx, r8, r9 或ecx
```
ROPgadget --binary dhcpd.bin --only "pop|ret" | grep "rcx"
ROPgadget --binary dhcpd.bin --only "mov|pop|ret" | grep "rcx"
ROPgadget --binary dhcpd.bin | grep -v "jmp" | grep "ret" | grep "r8"
xchg

```

设置可控参数，然后调用check_argv

| register | value    |
| -------- | -------- |
| rdi      | 0x100001 |
| rsi      | 0x100002 |
| rdx      | 0x100003 |
| rcx      | 0x100004 |
| r8       | 0x100005 |
| r9       | 0x100006         |
