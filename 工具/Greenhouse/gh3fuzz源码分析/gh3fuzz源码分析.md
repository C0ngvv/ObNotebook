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

