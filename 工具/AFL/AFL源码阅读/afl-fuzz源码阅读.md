直接看main函数，首先解析参数，设置Qemu模式时，设置`qemu_mode`标志为1。

```
while ((opt = getopt(argc, argv, "+i:o:f:m:b:t:T:dnCB:S:M:x:QV")) > 0)
```

setup_signal_handlers(); 设置信号处理器;

check_asan_opts();  检查ASAN选项（通过获取环境变量`ASAN_OPTIONS`和`MSAN_OPTIONS`的内容）;

主要的是设置输出和同步目录setup_dirs_fds()，然后读取测试用例并添加到队列里read_testcases(),

### P1. 是怎么用Qemu运行程序的？

可能是使用`afl-qemu-trace`，设置一些参数`afl-qemu-trace -- binary`

### P2. AFL的工作流程

### P3. AFL的位图是什么，如何计算，有什么作用？

### P4. AFL是如何变异的？

### P5. AFL是如何将输入数据送到程序的？Qemu模式是如何送的？






