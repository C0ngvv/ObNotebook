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
还是先回到`build_fuzz_img.py`文件，在main函数创建了`FuzzerBuilder`对象，然后调用了`build()`方法，该方法总共调用了5个操作，如下。
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