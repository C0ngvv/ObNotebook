```c
alf-fuzz -i input_dir -o output_dir -Q -m none binary
```
### getopt()参数解析
`-i`

```c
afl->in_dir = optarg;
if (!strcmp(afl->in_dir, "-")) { afl->in_place_resume = 1; }
```

`-o`
afl->out_dir = optarg;

`-Q`
```c
if (afl->fsrv.qemu_mode) { FATAL("Multiple -Q options not supported"); }
afl->fsrv.qemu_mode = 1;
if (!mem_limit_given) { afl->fsrv.mem_limit = MEM_LIMIT_QEMU; }
```

`-m none`
```c
afl->fsrv.mem_limit = 0;
```

ALF_PRELOAD
```c
/* afl-qemu-trace takes care of converting AFL_PRELOAD. */
```

```
拷贝原始命令行
创建output目录下的各种目录和文件
init_count_class16();
...
setup_cmdline_file(afl, argv + optind); //向cmdline写入命令行
read_testcases(afl, NULL);  


```

### read_testcases()




代码中unlikely()的作用，用于编译优化，表示这条语句发生的概率低。
"in place resume" 是指一种特定的 fuzzing 模式，它允许 fuzzing 进程在之前的状态基础上继续执行，而不需要重新从头开始。
