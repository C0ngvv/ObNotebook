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