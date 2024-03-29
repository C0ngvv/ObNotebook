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
pivot_inputs(afl);  //种子硬链接在output/queue目录下并改名为id:形式
afl->tmp_dir = afl->out_dir;
check_binary(afl, argv[optind]);  //检测输入文件是否为ELF可执行，检测是否插桩等，持久化检查等
use_argv = get_qemu_argv(argv[0], &afl->fsrv.target_path, argc - optind, argv + optind);  // 返回类似：afl-qemu-trace -- target_path_p argv
//一些设置realloc, memset..
//cmplog_binary  不知道干啥的
load_auto(afl);  /* Load automatically generated extras. */似乎加载自动发现的字典token
load_extras(afl, extras_dir[i]);  // /* Read extras from the extras directory and sort them by size. */ 不知道干啥的
deunicode_extras(afl);  //有时需要unicode解码
dedup_extras(afl);  //去重
afl->in_bitmap  //bitmap相关
perform_dry_run(afl);  //运行所以测试用例验证app是否正常工作
	calibrate_case(afl, q, use_mem, 0, 1);  //Calibrate a new test case.
		afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon, afl->afl_env.afl_debug_child); //启动forkserver
		write_to_testcase(afl, (void **)&use_mem, q->len, 1);
		fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);
		位图处理等
cull_queue(afl);
show_init_stats(afl);
find_start_position(afl);
load_stats_file(afl);
write_stats_file(afl, 0, 0, 0, 0);
maybe_update_plot_file(afl, 0, 0, 0);
save_auto(afl);
while:
	cull_queue(afl);
	..
	fuzz_one(afl);
	
```




代码中unlikely()的作用，用于编译优化，表示这条语句发生的概率低。
"in place resume" 是指一种特定的 fuzzing 模式，它允许 fuzzing 进程在之前的状态基础上继续执行，而不需要重新从头开始。
