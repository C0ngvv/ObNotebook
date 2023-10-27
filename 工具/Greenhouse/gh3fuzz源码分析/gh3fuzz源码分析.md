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

还是先回到`build_fuzz_img.py`文件，在main函数创建了`FuzzerBuilder`对象，然后调用了`build()`方法，该方法总共调用了5个操作，如下。
```    python
	def build(self):
        self._get_info()
        self._extract_dict()
        self._assemble_fuzz_script()
        self._assemble_dockerfile()
        self._build_docker()
```

