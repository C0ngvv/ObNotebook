Greenhouse执行模糊测试的命令如下，先调用`build_fuzz_img.py`构建一个用于模糊测试的镜像，然后运行进行模糊测试。
```bash
python3 build_fuzz_img.py -f <path-to-rehosted-greenhouse-image.tar.gz> 
docker run --privileged fuzzing_dude_img
```

查看Dockerfile文件，最终构建好环境后是运行`entrypoint.sh`文件。
```
from docker:dind

workdir /root
run apk add python3 py3-jinja2 py3-pip aws-cli
run pip install sonyflake-py pymongo
add fuzz_bins /root/fuzz_bins
add templates /root/templates
add entrypoint.sh /root/entrypoint.sh
add build_fuzz_img.py /root/build_fuzz_img.py
add fuzz_gh.sh /root/fuzz_gh.sh
entrypoint ["/root/entrypoint.sh"]
```

## build_fuzz_img.py
还是先回到`build_fuzz_img.py`文件，在main函数创建了`FuzzerBuilder`对象，这个类有`__enter__()`方法。
### \_\_enter\_\_()
- 首先它创建一个gh-开头的临时工作目录，解包固件运行环境到工作目录
- 然后查找所有config.json文件（Greenhouse重托管时生成的文件）并加载保存为`self.config`
- 设置`self.img_dir`目录为minimal目录，并在该目录写入简单修改后的`config.json`文件。
```python
    def __enter__(self):
        self.workdir = tempfile.TemporaryDirectory(prefix="gh-")
        os.system(f"tar -xf {self.fw_path} -C {self.workdir.name}")
        tmp = glob.glob(os.path.join(self.workdir.name, "*", "*", "config.json"))
        assert len(tmp) == 1
        config_path = tmp[0]
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        self.img_dir = os.path.join(os.path.dirname(config_path), "minimal")
        with open(os.path.join(self.img_dir, 'config.json'), 'w') as f:
            config = self.config.copy()
            old_ip = self.config['targetip']
            config["targetip"] = "0.0.0.0"
            config["loginurl"] = config["loginurl"].replace(old_ip, "0.0.0.0")
            json.dump(config, f, indent=4)
        return self
```

创建对象后调用了`build()`方法，该方法总共调用了5个操作，如下。
```    python
	def build(self):
        self._get_info()
        self._extract_dict()
        self._assemble_fuzz_script()
        self._assemble_dockerfile()
        self._build_docker()
```

### \_get_info()
这个方法的作用是根据通过Greenhouse生成重托管环境Dockerfile中的CMD命令行提取出运行的架构和程序执行参数命令行信息。
```python
    def _get_info(self):
        """
        extract the architecture
        TODO: do it properly
        """
        dockerfile = os.path.join(self.img_dir, "Dockerfile")
        assert os.path.exists(dockerfile)
        with open(dockerfile, 'r') as f:
            for line in f:
                if 'CMD' in line:
                    # extract arch
                    res = re.search("qemu-(.*)-static", line)
                    arch = res.group(1)
                    self._arch = arch

                    # extract command
                    cmd_argv = json.loads(line.split(maxsplit=1)[1])
                    assert '--' in cmd_argv
                    cmd_argv = cmd_argv[cmd_argv.index('--')+1:]
                    self._cmd = ' '.join(cmd_argv)
                    return
            else:
                raise RuntimeError("????")
```

### \_extract_dict()
\_extract_dict()的主要作用是通过`strings`提取出目标二进制程序中的字符串，并进行一些简单过滤（如包含非打印字符，包含引号等），将这些字符串保存为字典文件。
```python
    def _extract_dict(self):
        bin_path = os.path.join(self.img_dir, "fs", os.path.relpath(self.config['targetpath'], "/"))
        assert os.path.exists(bin_path)
        strs = subprocess.getoutput(f"strings {bin_path}").splitlines()
        strs = [x for x in strs if "'" not in x and '"' not in x] # avoid troubles
        strs = ["GET", "POST", "/", "HTTP"] + strs
        strs = list(set(strs))
        with open(os.path.join(self.img_dir, "dictionary"), "w") as f:
            for i, s in enumerate(strs):
                if any(x in list(s.encode()) for x in list(range(128, 256))+list(range(1, 32))):
                    continue
                f.write(f'str{i}="{s}"\n')
```

### \_assemble_fuzz_script()
配置模糊测试background脚本。
### \_assemble_dockerfile()
这个方法用于配置dockerfile文件，首先读取重托管环境中的Dockerfile文件，然后按照一定的改变再重新写入
```python
    def _assemble_dockerfile(self):
        with open(os.path.join(self.img_dir, "Dockerfile")) as f:
            lines = f.read().splitlines()
        with open(os.path.join(self.img_dir, "Dockerfile"), 'w') as f:
            for line in lines:
                if line.startswith("FROM"): # prologue
                    f.write("FROM scratch\n")
                elif line.startswith("ENTRYPOINT"): # skip
                    continue
                elif line.startswith("CMD"): # epilogue
                    f.write("COPY config.json /config.json\n")
                    f.write("COPY fuzz_bins /fuzz_bins\n")
                    f.write("COPY seeds /fuzz/seeds\n")
                    f.write("COPY dictionary /fuzz/dictionary\n")
                    f.write("COPY fuzz.sh /fuzz.sh\n")
                    f.write("COPY postauth_fuzz.sh /postauth_fuzz.sh\n")
                    f.write("COPY finish.sh /finish.sh\n")
                    f.write("COPY minify.sh /minify.sh\n")
                    f.write(f'RUN ["/fuzz_bins/utils/cp", "/fuzz_bins/qemu/afl-qemu-trace-{self._arch}", "/usr/bin/afl-qemu-trace"]\n')
                    f.write("WORKDIR /scratch\n")
                    f.write("CMD /fuzz.sh\n")
                    continue
                else:
                    f.write(line+"\n")
```

### \_build_docker()
构建docker容器。首先复制种子文件，然后复制fuzz_bins文件，这些由fuzz_bins_src目录源码构建生成，然后创建容器。
```python
    def _build_docker(self):
        # copy seeds
        src_path = os.path.join(os.path.dirname(__file__), "fuzz_bins", "seeds")
        dst_path = os.path.join(self.img_dir, "seeds")
        os.system(f"cp -r {src_path} {dst_path}")

        # copy fuzz_bins
        src_path = os.path.join(os.path.dirname(__file__), "fuzz_bins")
        dst_path = os.path.join(self.img_dir, "fuzz_bins")
        os.system(f"cp -r {src_path} {dst_path}")

        # do the honor
        ret = subprocess.call(["docker", "build", "-t", self.img_name, "."], cwd=self.img_dir)
        assert ret == 0
```

## 执行
执行后创建docker时的目录如下
![](images/Pasted%20image%2020231113152431.png)

fuzz_bins目录提供了模糊测试所使用的程序，如afl-fuzz等。

其中Dockerfile文件内容
```
FROM scratch
ADD fs /

ENV LD_PRELOAD=libnvram-faker.so

EXPOSE 80/tcp
EXPOSE 80/udp
EXPOSE 1900/tcp
EXPOSE 1900/udp

COPY config.json /config.json
COPY fuzz_bins /fuzz_bins
COPY seeds /fuzz/seeds
COPY dictionary /fuzz/dictionary
COPY fuzz.sh /fuzz.sh
COPY postauth_fuzz.sh /postauth_fuzz.sh
COPY finish.sh /finish.sh
COPY minify.sh /minify.sh
RUN ["/fuzz_bins/utils/cp", "/fuzz_bins/qemu/afl-qemu-trace-arm", "/usr/bin/afl-qemu-trace"]
WORKDIR /scratch
CMD /fuzz.sh
```

### 错误信息
```bash
ubuntu@ubuntu22:/sys/devices/system/cpu$ sudo docker run --privileged ac1450fuzz
[Fuzz] Launch background scripts...
    - settng up dev nodes in  /ghdeV
cp: can't create '/etc/hosts': File exists
cp: can't create '/etc/resolv.conf': File exists
[Fuzz] Dry run the server...
Terminated
GH_SUCCESSFUL_BIND
[Fuzz] Dry run the server again to obtain the address for forkserver...
Terminated

[GH_ERROR] something wrong with afl+GH!!!
[HOOK] 1337 1338 [HOOK2] 1337 1338 [qemu] hackdev - changing /dev/urandom to /ghdev/urandom
[Fuzz] Trying without unshare

[GH_ERROR] something wrong with afl+GH!!!
[HOOK] 1337 1338 [HOOK2] 1337 1338 [qemu] hackdev - changing /dev/urandom to /ghdev/urandom Segmentation fault (core dumped)
[GH_ERROR] Giving up
```

后来发现是Netgear固件/tmp/shm_id的问题，重新设置并且运行`echo core > /proc/sys/kernel/core_pattern`后就可以跑起来模糊测试了，跑起来的信息如下。

```bash
ubuntu@ubuntu22:/tmp/AC1450Docker/minimal/fs$ sudo docker run --privileged ac1450fuzz
[Fuzz] Launch background scripts...
    - settng up dev nodes in  /ghdev
cp: can't create '/etc/hosts': File exists
cp: can't create '/etc/resolv.conf': File exists
[Fuzz] Dry run the server...
Terminated
GH_SUCCESSFUL_BIND
[Fuzz] Dry run the server again to obtain the address for forkserver...
return addr: 0x00012cf8
[Fuzz] Start Fuzzing...
[+] Enabled environment variable AFL_NO_AFFINITY with value 1
afl-fuzz++4.02a based on afl by Michal Zalewski and a large online community
[+] afl++ is maintained by Marc "van Hauser" Heuse, Heiko "hexcoder" Eißfeldt, Andrea Fioraldi and Dominik Maier
[+] afl++ is open source, get it at https://github.com/AFLplusplus/AFLplusplus
[+] NOTE: This is v3.x which changes defaults and behaviours - see README.md
[+] No -M/-S set, autoconfiguring for "-S default"
[*] Getting to work...
[+] Using exponential power schedule (FAST)
[+] Enabled testcache with 50 MB
[+] Generating fuzz data with a length of min=1 max=1048576
[*] Checking core_pattern...
[!] WARNING: Could not check CPU scaling governor
[+] Looks like we're not running on a tty, so I'll be a bit less verbose.
[+] You have 8 CPU cores and 1 runnable tasks (utilization: 12%).
[+] Try parallel jobs - see docs/parallel_fuzzing.md.
[*] Setting up output directories...
[!] WARNING: Not binding to a CPU core (AFL_NO_AFFINITY set).
[*] Scanning '/scratch/seeds'...
[+] Loaded a total of 5 seeds.
[*] Creating hard links for all input files...
[*] Validating target binary...
[*] No auto-generated dictionary tokens to reuse.
[*] Loading extra dictionary from '/scratch/dictionary' (level 0)...
[!] WARNING: Invalid escaping (not \xNN) in line 678.
[!] WARNING: Keyword too big in line 1514 (559 B, limit is 128 B)
[!] WARNING: Invalid escaping (not \xNN) in line 1561.
[!] WARNING: Invalid escaping (not \xNN) in line 1831.
[!] WARNING: Keyword too big in line 2233 (993 B, limit is 128 B)
[!] WARNING: Keyword too big in line 3427 (769 B, limit is 128 B)
[*] Loaded 4028 extra tokens, size range 1 B to 93 B.
[!] WARNING: Some tokens are relatively large (93 B) - consider trimming.
[!] WARNING: More than 256 tokens - will use them probabilistically.
[+] Loaded a total of 4027 extras.
[*] Attempting dry run with 'id:000000,time:0,execs:0,orig:9925'...
[*] Spinning up the fork server...
[+] All right - fork server is up.
[*] Target map size: 65536
[!] WARNING: instability detected during calibration
    len = 171, map size = 406, exec speed = 1603 us
[!] WARNING: Instrumentation output varies across runs.
[*] Attempting dry run with 'id:000001,time:0,execs:0,orig:9050'...
    len = 42, map size = 95, exec speed = 1214 us
[*] Attempting dry run with 'id:000002,time:0,execs:0,orig:161161'...
    len = 1155, map size = 457, exec speed = 3772 us
[*] Attempting dry run with 'id:000003,time:0,execs:0,orig:161160'...
    len = 447, map size = 95, exec speed = 893 us
[!] WARNING: No new instrumentation output, test case may be useless.
[*] Attempting dry run with 'id:000004,time:0,execs:0,orig:10853'...
    len = 954, map size = 452, exec speed = 2970 us
[+] All test cases processed.
[!] WARNING: Some test cases look useless. Consider using a smaller set.
[+] Here are some useful stats:

    Test case count : 4 favored, 1 variable, 1 ignored, 5 total
       Bitmap range : 95 to 457 bits (average: 301.00 bits)
        Exec timing : 1214 to 3772 us (average: 1978 us)

[*] -t option specified. We'll use an exec timeout of 1000 ms.
[+] All set and ready to roll!
[*] Entering queue cycle 1.
[*] Fuzzing test case #0 (5 total, 0 crashes saved, perf_score=150, exec_us=1603, hits=0, map=406, ascii=0)...
[*] Fuzzing test case #18 (34 total, 0 crashes saved, perf_score=112, exec_us=3614, hits=1, map=588, ascii=0)...
[*] Fuzzing test case #17 (35 total, 0 crashes saved, perf_score=150, exec_us=2556, hits=1, map=580, ascii=0)...
[*] Fuzzing test case #1 (36 total, 0 crashes saved, perf_score=25, exec_us=1214, hits=0, map=95, ascii=0)...
[*] Fuzzing test case #19 (36 total, 0 crashes saved, perf_score=100, exec_us=1416, hits=2, map=402, ascii=0)...
[*] Fuzzing test case #31 (36 total, 0 crashes saved, perf_score=37, exec_us=905, hits=6, map=129, ascii=0)...
[*] Fuzzing test case #21 (37 total, 0 crashes saved, perf_score=100, exec_us=1668, hits=11, map=407, ascii=0)...
[*] Fuzzing test case #33 (37 total, 0 crashes saved, perf_score=75, exec_us=3141, hits=3, map=421, ascii=0)...
[*] Fuzzing test case #26 (37 total, 0 crashes saved, perf_score=100, exec_us=1827, hits=1, map=407, ascii=0)...
[*] Fuzzing test case #24 (37 total, 0 crashes saved, perf_score=75, exec_us=3608, hits=1, map=499, ascii=0)...
[*] Fuzzing test case #34 (37 total, 0 crashes saved, perf_score=100, exec_us=2505, hits=1, map=482, ascii=0)...
[*] Fuzzing test case #37 (38 total, 0 crashes saved, perf_score=200, exec_us=1422, hits=2, map=417, ascii=0)...
[*] Fuzzing test case #12 (38 total, 0 crashes saved, perf_score=100, exec_us=1469, hits=8, map=401, ascii=0)...
[*] Fuzzing test case #32 (38 total, 0 crashes saved, perf_score=100, exec_us=1252, hits=17, map=413, ascii=0)...
[*] Fuzzing test case #29 (38 total, 0 crashes saved, perf_score=100, exec_us=1844, hits=1, map=399, ascii=0)...
[*] Fuzzing test case #4 (38 total, 0 crashes saved, perf_score=75, exec_us=2970, hits=0, map=452, ascii=0)...
[*] Fuzzing test case #22 (38 total, 0 crashes saved, perf_score=75, exec_us=4376, hits=12, map=543, ascii=0)...
[*] Fuzzing test case #2 (38 total, 0 crashes saved, perf_score=75, exec_us=3772, hits=0, map=457, ascii=0)...
```

只是输入数据是如何喂给httpd程序的？afl++经过作者修改过，并对网络套接字部分进行了处理。

## Crash分析
经过几个小时的模糊测试后出现了十多个crash，但是这些crash很可能是因为仿真环境异常所导致的崩溃，而不是真实的漏洞。

id:000000,sig:11,src:000153,time:13861385,execs:1863019,op:havoc,rep:8
```
POS /shareswwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwTwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwp;\r\nConespnhT tznt-LengtW: 13\r\n\r\ntestJtes\xce\r\n\x7f\n
```

![](images/Pasted%20image%2020231030151718.png)

![](images/Pasted%20image%2020231030151732.png)

## afl_gh.patch源码分析
分析目标：如何将网络套接字转变为AFL++文件数据流。

### do_accept4()
以do_accept4()为例，这个hook的主要功能应该是：
- 复制stdin_fd文件描述符作为返回的文件描述符(27行)
- 修改参数target_addr设置为127.0.0.1：4444（38行）
```diff
 static abi_long do_accept4(int fd, abi_ulong target_addr,
                            abi_ulong target_addrlen_addr, int flags)
 {
@@ -3524,6 +3737,45 @@ static abi_long do_accept4(int fd, abi_ulong target_addr,
     abi_long ret;
     int host_flags;
 
+    if(hookhack) {
+        struct sockaddr_in sin;
+        socklen_t len = sizeof(sin);
+        uint16_t port = 0;
+        // int new_fd = -1;
+        if(conn_fd != -1) {
+            fputs("[HOOK] deny subsequent accept calls!\n", bk_stdout);
+            return -EAGAIN;
+        }
+
+        fputs("[HOOK] accept hooked!\n", bk_stdout);
+        if(getsockname(fd, (struct sockaddr *)&sin, &len)) goto out;
+        port = ntohs(sin.sin_port);
+        fprintf(bk_stdout, "[HOOK] accept at port: %d\n", port);
+        if(port != 80) goto out;
+        if(hookhack_recved) {
+            fputs("[HOOK] done!\n", bk_stdout);
+            exit(0);
+        }
+        conn_fd = dup(bk_stdin_fd);
+        fprintf(bk_stdout, "[HOOK] accept sock fd: %d\n", conn_fd);
+
+        // fake connection source
+        if (get_user_u32(addrlen, target_addrlen_addr))
+            return -TARGET_EFAULT;
+        struct sockaddr_in saddr = {0};
+        fputs("[HOOK] getsockname invoked!\n", bk_stdout);
+        saddr.sin_family = AF_INET;
+        saddr.sin_port = htons(4444);
+        inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);
+        host_to_target_sockaddr(target_addr, (void *)&saddr, addrlen);
+        if (put_user_u32(addrlen, target_addrlen_addr)) return -TARGET_EFAULT;
+
+        hookhack_done++;
+        if(getenv("GH_DRYRUN")) gh_dryrun_done = true;
+        return conn_fd;
+out:
+    }
```

除此之外，还对do_poll(), do_select()等进行了hook，以及对qemu进行的修改也在这里进行了，如do_openat()等。

## 融入Grammar Mutator

### 尝试在主机上chroot运行
首先依照Dockerfile拷贝相应的文件到fs中
```
COPY config.json /config.json
COPY fuzz_bins /fuzz_bins
COPY seeds /fuzz/seeds
COPY dictionary /fuzz/dictionary
COPY fuzz.sh /fuzz.sh
COPY postauth_fuzz.sh /postauth_fuzz.sh
COPY finish.sh /finish.sh
COPY minify.sh /minify.sh
RUN ["/fuzz_bins/utils/cp", "/fuzz_bins/qemu/afl-qemu-trace-arm", "/usr/bin/afl-qemu-trace"]
```

然后进入fs中，chroot，根据fuzz.sh脚本顺次运行命令
```
sudo chroot . ./greenhouse/busybox sh
```

当运行到下面这条命令时，就出现问题了，错误提示如下图所示
```
/usr/bin/afl-qemu-trace -hookhack -hackbind -hackproc -execve "/qemu-static -hackbind -hackproc" -- $CMD 2>&1
```

![](images/Pasted%20image%2020231113215135.png)

发现这段代码在afl_gh.patch(文件105行)中：
```
+    main_bin_start = info->start_code;
+    main_bin_end = info->end_code;
+
+    bk_stdin_fd = dup2(0, 1337);
+    bk_stdout_fd = dup2(1, 1338);
+    if(bk_stdin_fd < 0 || bk_stdout_fd < 0) {
+        puts("Error when backing up stdin and stdout");
+        _exit(EXIT_FAILURE);
+    }
```

经查询，dup2(oldfd, newfd)用于复制文件描述符使得newfd指向与oldfd相同的文件，dup2(0,1337)使得文件描述符1337指向标准输入，从而可以在后续代码中使用1337来读取标准输入的内容。

```
`dup2()`函数在以下情况下可能会调用失败：

1. `oldfd`无效：如果`oldfd`不是有效的文件描述符（小于0或超出了进程打开文件描述符的最大限制），则`dup2()`会调用失败。
2. `newfd`无效：如果`newfd`不是有效的文件描述符（小于0或超出了进程打开文件描述符的最大限制），则`dup2()`会调用失败。
3. `newfd`与 `oldfd` 相等：如果`newfd`等于`oldfd`，则`dup2()`不进行任何操作，并返回`newfd`。
4. 不具备权限：如果进程没有足够的权限来复制文件描述符，比如试图复制一个只读文件描述符到一个只写文件描述符中，`dup2()`会调用失败。
5. 打开文件描述符数量超过系统限制：如果进程已打开的文件描述符数量超过了系统的限制，`dup2()`会调用失败。

在`dup2()`调用失败时，它会返回-1，并设置`errno`变量来指示具体的失败原因。因此，可以通过检查`errno`的值来确定具体的失败原因。
```

我猜测可能是权限不足的问题，或者资源限制。

尝试一下不在chroot能不能运行，不行。

![](images/Pasted%20image%2020231113221520.png)

通过afl对固件进行模糊测试必须在固件根目录下启动模糊测试，否则会出现很多异常问题，因为固件程序依据固件根目录而非主机根目录来寻找信息。

### 尝试在docker上运行
使用正常gh3fuzz创建的docker环境启动后会自动运行fuzz.sh脚本开始模糊测试，当出现异常时就会停止环境。为了持续稳定的进入docker shell内进行分析，创建Docker image的时候不让它运行fuzz.sh脚本。



向docker中加入语法变异库so后，不断递归提示缺少库。这个库一直找不到应该放在哪儿，里面放了这个库还是提示这个错误。

![](images/Pasted%20image%2020231113165031.png)
