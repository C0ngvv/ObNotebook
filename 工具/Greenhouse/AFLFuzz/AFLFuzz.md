
```bash
git clone https://github.com/AFLplusplus/AFLplusplus.git
```

greenhouse/gh3fuzz的afl-common.c与原始的区别就在于更改了get_qemu_argv()。

![](AFLFuzz/image-20240109091130257.png)

将新版的afl++的该文件中的这个函数替换掉，随后再重新编译。

```bash
STATIC=1 make distrib
```

随后遇到as问题
```bash
[+] Instrumented 665 locations (64-bit, non-hardened mode, ratio 100%).
afl-as++4.10a by Michal Zalewski

[-] PROGRAM ABORT : Endless loop when calling 'as' (remove '.' from your PATH)
         Location : main(), src/afl-as.c:636

make[1]: *** [GNUmakefile.llvm:399: instrumentation/afl-common.o] Error 1
make[1]: Leaving directory '/home/ubuntu/Desktop/firmafl/AFLplusplus'
make: [GNUmakefile:334: llvm] Error 2 (ignored)
[-] Compiling afl-cc failed. You seem not to have a working compiler.
make: *** [GNUmakefile:335: llvm] Error 1
```

这时因为当前目录的as与`/usr/bin/as`冲突了
```bash
ubuntu@ubuntu22:~/Desktop/firmafl/AFLplusplus$ which as
./as
ubuntu@ubuntu22:~$ which as
/usr/bin/as
ubuntu@ubuntu22:~/Desktop/firmafl/AFLplusplus$ $PATH
bash: /home/ubuntu/.local/bin:.:/usr/local/jdk-17.0.7/bin:/usr/local/jdk-17.0.7/lib:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/home/ubuntu/.local/bin/:/snap/bin: No such file or directory
```

为此，我将AFL++中的`as`暂时改名为了`aflas`
```bash
ubuntu@ubuntu22:~/Desktop/firmafl/AFLplusplus$ ls -l as
lrwxrwxrwx 1 ubuntu ubuntu 6  1月  9 09:15 as -> afl-as
ubuntu@ubuntu22:~/Desktop/firmafl/AFLplusplus$ mv as aflas
ubuntu@ubuntu22:~/Desktop/firmafl/AFLplusplus$ ls -l aflas
lrwxrwxrwx 1 ubuntu ubuntu 6  1月  9 09:15 aflas -> afl-as
```
