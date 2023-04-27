
## AFL模糊测试网络数据包过程
在源码`FirmAFL_config/user.sh`中包含了alf-fuzz的调用命令
```
AFL="./afl-fuzz -m none -t 800000+ -Q -i ./inputs -o ./outputs -x keywords"
echo $AFL

chroot . \
${AFL} \
/bin/busybox @@
```

`-t`设置超时，单位ms； `-x` 设置字典

即它使用文件，但是`AFL`没有指定要模糊的程序，所以实际命令是这样吗：
```
chroot . ./afl-fuzz -m none -t 800000+ -Q -i ./inputs -o ./outputs -x /bin/busybox @@
```

为什么是对`busybox` 进行模糊测试，`inputs`下是什么

查看代码发现`inputs`拷贝于`FirmAFL_config\id\seed` ，打开9925的查看，里面内容是HTTP数据包。
```
GET /session_login.php HTTP/1.1
Accept-Encoding: gzip,deflate,sdchzywzywzywzywzywzywzywzywzyw
Host: 192.168.0.50
Cookie: uid=zywzyw
Content-Length: 13

test=test
```

大部分seed的内容是一行字符串：
```
zywzywzywzywzywzywzywzywzywzyw
```

顺一遍流程，start.py文件
```
id=sys.argv[1]

cmdstr ="./run.sh"
subprocess.Popen(cmdstr,stdin=subprocess.PIPE, stdout=subprocess.PIPE,shell=True)
time.sleep(80)
cmdstr ="python test.py"
os.system(cmdstr)
time.sleep(4)
cmdstr ="./user.sh"
os.system(cmdstr)
```

首先运行`run.sh` 启动qemu仿真，`subprocess.Popen`可以产生子进程，并连接到子进程的标准输入输出错误中，还可以得到子进程的返回值。`shell`设置成`True`，指定的命令会在shell里解释执行;`stdin` ,`stdout`和`stderr`，分别表示子程序的标准输入、标准输出和标准错误，`subprocess.PIPE` 表示创建一个新的管道