---
title: AFL forkserver工作原理
date: 2024/01/05
categories: 
tags:
---
# AFL forkserver工作原理

![](AFL%20forkserver工作原理/image-20240105222658806.png)

## init_forkserver
`init_forkserver`为forkserver代码，首先它们通过管道进行通信，在afl-fuzz中通过fork出一个子进程，该子进程进行一些设置后启动测试的目标程序，其中测试的目标程序经过AFL插桩，主要插桩代码在`_afl_maybe_log`。
```c
EXP_ST void init_forkserver(char** argv) {
  // 初始化状态管道和控制管道
  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  // unix编程,操作系统提供的系统调用,子进程为forkserver()
  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");
  
  // 子进程的初始化
  if (!forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */
       
	// 如果执行失败主进程将通过trace_bits = EXEC_FAIL_SIG（位于bitmap）获得信息
    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  // 主进程的pipe为fsrv_ctl_fd = ctl_pipe[1]用于写;
  // fsrv_st_fd = st_pipe[0]用于读; 
  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);
  
  // 如果长度刚好是4位,一切正常,可以直接返回
  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", doc_path);

    } else if (!mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", doc_path);

  } else if (!mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv(DEFER_ENV_VAR) ? "three" : "two",
         getenv(DEFER_ENV_VAR) ?
         "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
         "      reached before the program terminates.\n\n" : "",
         DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}
```

## \_afl_maybe_log
`_afl_maybe_log`是插桩在目标程序中的汇编代码，下面是C伪代码，在forkserver创建并启动目标程序后就执行到了`_afl_maybe_log`，第一次的话它会进行初始化，然后向父进程写入4字节表示初始化完成，然后进入while循环，等待父进程发送指令（接收4字节）表示要进行新的测试。当forkserver接收到指令后，就对当前进程进行fork，得到当前进程和当前进程的子进程。当前进程即forkserver会向父进程发送4字节表示子进程启动成功，然后通过waitpid()等待子进程执行完，而子进程则执行收集覆盖率，当forkserver等子进程执行完后再向父进程发送4字节表示子进程执行完。

```c
// 与 fuzzer 通用的 pipe (1)
#define READ_PIPE_FD 198
#define WRITE_PIPE_FD 199

char _afl_maybe_log(__int64 a1, __int64 a2, __int64 a3, __int64 bbid)
{
    // 是否需要初始化 (2)
    if ( !_afl_area_ptr )
    {
        // 取得 shared memory (3)
        shmid_str = getenv("__AFL_SHM_ID");
        shmid_int = atoi(shmid_str);
        shm = shmat(shmid_int, NULL, 0);
        _afl_area_ptr = shm;

        // handshake (4)
        if ( write(WRITE_PIPE_FD, &_afl_temp, 4) == 4 )
        {
            // --------------- fork server (5) ---------------
            while ( 1 )
            {
                if ( read(READ_PIPE_FD, &_afl_temp, 4) != 4 ) // (6)
                    break;
                pid = fork();
                if ( !pid )
                    goto __afl_fork_resume;

                write(WRITE_PIPE_FD, &pid, 4);
                waitpid(pid, &_afl_temp, 0); // (7)
                write(WRITE_PIPE_FD, &_afl_temp, 4);
            }
            _exit(0);
        }
    }
    __afl_fork_resume: // (8)
    // 收集 coverage
    edge = _afl_prev_loc ^ bbid;
    _afl_prev_loc = (_afl_prev_loc ^ edge) >> 1;
    ++*(_afl_area_ptr + edge);
}
```

## 如何将变异数据发送给fork的目标程序
在init_forkserver中，forkserver执行了`execv(target_path, argv);`，即目标程序和其执行参数，奇怪的是那么每次启动目标程序其参数不是就固定了吗(`argv`)，如何为目标程序指定每次变异的测试用例呢？

实际上目标程序每次执行都是读取的相同的文件：`out_dir/.cur_input`内容，只是每次测试时该文件里面的内容会被写入不同的测试用例。

## 变异
AFL的变异代码位于fuzz_one中，

以位反转为例，AFL通过宏来定义位反转操作
```c
#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
```

通过for循环来遍历每一位依次调用`FLIP_BIT`对当前测试用例`out_buf`进行位反转，然后调用`common_fuzz_stuff`用于对当前测试用例`out_buf`执行依次测试，执行完后再调用依次`FLIP_BIT`来还原原始测试用例，从而下一次只对下一位进行反转。
```c
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    stage_cur_byte = stage_cur >> 3;
    FLIP_BIT(out_buf, stage_cur);
    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    FLIP_BIT(out_buf, stage_cur);
    ...
```

`common_fuzz_stuff()`用于执行一次测试。它首先调用`write_to_testcase()`来将本次测试输入写入每次模糊测试过程中二进程读取的指定的outfile中。然后`run_target()`会执行一次目标程序，其具体流程为：先给forkserver发送4字节表示开始一次新的测试，当forkserver启动新的二进制程序后会向父程序（本程序）发送新程序的pid值，随后会等待forkserver发送4字节数据表示子程序执行完，后面就是计算覆盖率了。执行完`run_target()`后面就是对这次执行进行一些判断，看看当前测试用例是否interesting而保留，更新显示状态。
```c
EXP_ST u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  if (post_handler) {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;

  }

  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

     skip_requested = 0;
     cur_skipped_paths++;
     return 1;

  }

  /* This handles FAULT_ERROR for us: */

  queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}
```
## 参考链接
[2. AFL fuzz one函数 (yuque.com)](https://www.yuque.com/alipayxsmb67d6yg/qgmue5/odlo4wwyty4snnh2?singleDoc#KHCtP)

[AFL插桩机理 (yuque.com)](https://www.yuque.com/alipayxsmb67d6yg/qgmue5/lfglap3tkveqz4bx?singleDoc#iWrJa)

[AFL命令行中“@@“的作用以及AFL的两种数据传递方式_afl 测试@@-CSDN博客](https://blog.csdn.net/weixin_50972562/article/details/125536878)

[基于qemu和unicorn的Fuzz技术分析-腾讯云开发者社区-腾讯云 (tencent.com)](https://cloud.tencent.com/developer/article/1987935)

[AFL-Unicorn中的fork server机制详解_forkserver-CSDN博客](https://blog.csdn.net/Little_Bro/article/details/122694054)

[进程间的通信方式——pipe（管道）-CSDN博客](https://blog.csdn.net/skyroben/article/details/71513385)
