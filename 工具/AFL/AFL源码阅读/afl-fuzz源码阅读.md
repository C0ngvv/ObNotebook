直接看main函数，首先解析参数，设置Qemu模式时，设置`qemu_mode`标志为1。

```
while ((opt = getopt(argc, argv, "+i:o:f:m:b:t:T:dnCB:S:M:x:QV")) > 0)
```

setup_signal_handlers(); 设置信号处理器;

check_asan_opts();  检查ASAN选项（通过获取环境变量`ASAN_OPTIONS`和`MSAN_OPTIONS`的内容）;

主要的是设置输出和同步目录setup_dirs_fds()，然后读取测试用例并添加到队列里read_testcases(),







