Qiling框架extensions中写了一个afl.py，是对unicornafl.uc_afl_fuzz一些常用逻辑的wrapper，可以在qiling脚本中调用ql_afl_fuzz设置模糊测试配置，但真正跑起来模糊测试还是得安装AFLplusplus，用afl-fuzz命令行行启动。

## 1.环境安装
Qiling环境安装，这个命令是安装最新的dev版本。
```bash
pip3 install --user https://github.com/qilingframework/qiling/archive/dev.zip
```

AFLplusplus环境安装
```bash
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make
cd ./unicorn_mode
./build_unicorn_support.sh
```

Qiling的模糊测试引擎还是afl，使用qiling进行模糊测试就是编写一个qiling脚本运行程序，并使用ql_afl_fuzz()设置将afl文件输入以个性化的方式转变为程序输入，一般运行命令如下：
```bash
afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./fuzz_script.py @@
```

## 2.fuzz script案例与分析
### 2.1 案例1：fuzz linux_x8664程序
在Qiling提供的案例中（examples/fuzzing/linux_x8664）有一个针对二进制程序fuzz的，这是fuzz_x8664_linux.py脚本内容。
```python
#!/usr/bin/env python3
import os
import sys

from typing import Optional
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions import pipe
from qiling.extensions import afl

def main(input_file: str):
    ql = Qiling(["./x8664_fuzz"], "../../rootfs/x8664_linux",
        verbose=QL_VERBOSE.OFF, # keep qiling logging off
        console=False)          # thwart program output
    # redirect stdin to our mock to feed it with incoming fuzzed keystrokes
    ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())

    def place_input_callback(ql: Qiling, input: bytes, persistent_round: int) -> Optional[bool]:
        # feed fuzzed input to our mock stdin
        ql.os.stdin.write(input)
        # signal afl to proceed with this input
        return True

    def start_afl(ql: Qiling):
        afl.ql_afl_fuzz(ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    # get image base address
    ba = ql.loader.images[0].base
    # set afl instrumentation [re]starting point. we set it to 'main'
    ql.hook_address(callback=start_afl, address=ba + 0x1275)
    # this way afl will count stack protection violations as crashes
    ql.hook_address(callback=lambda x: os.abort(), address=ba + 0x126e)
    ql.run()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    main(sys.argv[1])
```

这是启动模糊测试运行命令
```bash
AFL_AUTORESUME=1 AFL_PATH="$(realpath ./AFLplusplus)" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./fuzz_x8664_linux.py @@
```

afl进行模糊测试时输入是文件输入，因此测试脚本中的__main__部分设置传进来一个参数作为文件名。在main方法中一方面设置让程序模拟运行起来，一方面将设置输入并让程序执行ql_afl_fuzz()。

- 首先将stdin重定向变为一个文件流`ql.os.stdin = pipe.SimpleInStream(sys.stdin.fileno())`
- 然后通过`ql.hook_address()`方法hook程序运行的main方法让其执行start_afl()
- 在生start_afl()中会调用`ql_afl_fuzz()`，参数包括`input_file`和`place_input_callback`
- 而`place_input_callback()`负责自定义将`input_file`中的内容变为程序输入，ql.exit_point表示的是调用run()方法时参数end的值
- 另一个hook的作用是对`___stack_chk_fail()`调用指令进行hook，当这条指令并执行时说明已经栈溢出了，这个设置调用`os.abort()`生成一个SIGABRT信号来使afl检测到并保存crash。

### 2.2 案例2：fuzz dlink_dir815
dir815_mips32el_linux.py是对hedwig.cgi程序进行模糊测试，这里与案例1不同的是该程序在这里是通过读取环境变量作为输入，所以创建Qiling对象时需要设置env。其次在处理输入时，它是通过通过关键字在内存中找到输入数据存储位置，然后通过`ql.mem.write`向该位置写入新的变异数据。
```python
#!/usr/bin/env python3
import os,sys
sys.path.append("../../..")
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.extensions.afl import ql_afl_fuzz

def main(input_file, enable_trace=False):

    env_vars = {
        "REQUEST_METHOD": "POST",
        "REQUEST_URI": "/hedwig.cgi",
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_COOKIE": "uid=1234&password="+"A" * 0x1000,  # fill up
        # "CONTENT_LENGTH": "8", # no needed
    }

    ql = Qiling(["./rootfs/htdocs/web/hedwig.cgi"], "./rootfs",
                verbose=QL_VERBOSE.DEBUG, env=env_vars, console=enable_trace)

    def place_input_callback(ql: Qiling, input: bytes, _: int):
        env_var = ("HTTP_COOKIE=uid=1234&password=").encode()
        env_vars = env_var + input + b"\x00" + (ql.path).encode() + b"\x00"
        ql.mem.write(ql.target_addr, env_vars)

    def start_afl(_ql: Qiling):
        """
        Callback from inside
        """
        ql_afl_fuzz(_ql, input_file=input_file, place_input_callback=place_input_callback, exits=[ql.os.exit_point])

    addr = ql.mem.search("HTTP_COOKIE=uid=1234&password=".encode())
    ql.target_addr = addr[0]

    main_addr = ql.os.elf_entry
    ql.hook_address(callback=start_afl, address=main_addr)

    try:
        ql.run()
        os._exit(0)
    except:
        if enable_trace:
            print("\nFuzzer Went Shit")
        os._exit(0)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    if len(sys.argv) > 2 and sys.argv[1] == "-t":
        main(sys.argv[2], enable_trace=True)
    else:
        main(sys.argv[1])
```

启动模糊测试运行命令
```bash
AFL_AUTORESUME=1 AFL_PATH="$(realpath ./AFLplusplus)" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python3 ./dir815_mips32el_linux.py @@
```

## 3.案例3：tenda-ac15
tenda ac15的案例我无法直接运行起来，因此我先尝试对其进行模拟，然后找到一个已知漏洞验证是否能构正常触发，最后再构建模糊测试。
### 3.1 固件模拟
#### 环境配置
模拟的脚本为：[qiling/examples/tendaac1518_httpd.py](https://github.com/qilingframework/qiling/blob/dev/examples/tendaac1518_httpd.py)
```python
#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# Setup:
# - Unpack firmware rootfs (assumed hereby: 'rootfs/tendaac15')
#   - AC15 firmware may be acquired from https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip
# - Refresh webroot directory:
#   - Enter the 'squashfs-root' directory
#   - rm -rf webroot
#   - mv webroot_ro webroot
# - Set network device
#   - Open "qiling/profiles/linux.ql"
#   - Set 'ifrname_override' to your hosting system network device name (e.g. eth0, lo, etc.)
#
# Run:
#  $ PYTHONPATH=/path/to/qiling ROOTFS=/path/to/tenda_rootfs python3 tendaac1518_httpd.py

import os
import socket
import threading

import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE


# user may set 'ROOTFS' environment variable to use as rootfs
ROOTFS = os.environ.get('ROOTFS', r'./rootfs/tendaac15')


def nvram_listener():
    server_address = fr'{ROOTFS}/var/cfm_socket'

    if os.path.exists(server_address):
        os.unlink(server_address)

    # Create UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(server_address)
    sock.listen(1)

    data = bytearray()

    with open('cfm_socket.log', 'wb') as ofile:
        while True:
            connection, _ = sock.accept()

            try:
                while True:
                    data += connection.recv(1024)

                    if b'lan.webiplansslen' not in data:
                        break

                    connection.send(b'192.168.170.169')

                    ofile.write(data)
                    data.clear()
            finally:
                connection.close()


def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    ql.add_fs_mapper(r'/dev/urandom', r'/dev/urandom')

    # $ gdb-multiarch -q rootfs/tendaac15/bin/httpd
    # gdb> set remotetimeout 100
    # gdb> target remote localhost:9999

    ql.run()


if __name__ == '__main__':
    nvram_listener_therad = threading.Thread(target=nvram_listener, daemon=True)
    nvram_listener_therad.start()

    my_sandbox([fr'{ROOTFS}/bin/httpd'], ROOTFS)
```

根据这个脚本最上面的说明操作：
- 下载固件并解压：[US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip](https://down.tenda.com.cn/uploadfile/AC15/US_AC15V1.0BR_V15.03.05.19_multi_TD01.zip)
- 利用binwalk解包固件，将squashfs-root改名为tendaac15并放入"rootfs"目录下
- 进入文件系统，删除webroot目录，将webroot_ro改名为webroot

网络服务我没用进行配置，我的环境是ubuntu 20.04，主机上有ens33网卡。

尝试运行这个脚本，可以跑起来，它开起的端口是8080，可用`netstat -an | grep :80`命令查看。但是当我用浏览器访问（`http://127.0.0.1:8080`）时，在成功返回页面前，qiling终端就出现error了。经过多次测试，有时候它能成功返回页面或者几次点击后然后出现error，大多数情况点击一下在返回前就error，总之它不能稳定的运行，这很影响我们对固件的分析。

出现的error有两种，大多数是`Syscall ERROR: ql_syscall_recv DEBUG: [Errno 11] Resource temporarily unavailable`，偶尔会出现`Syscall ERROR: ql_syscall_shutdown DEBUG: [Errno 107] Transport endpoint is not connected`。在网上查阅了资料无果，在qiling github页面上有人提出类似的[issue#1373](https://github.com/qilingframework/qiling/issues/1373)但无人解答。经过我的研究，对qiling的部分代码进行修改后解决了这两个问题，但是为了让我们能运行修改的qiling代码，我们需要先修改qiling的安装方式，如下：
```
wget https://github.com/qilingframework/qiling/archive/dev.zip
unzip dev.zip
cd qiling-dev
pip install -e .
```

#### BlockingIOError: \[Errno 11] Resource temporarily unavailable
运行报错如下：
```bash
[+] 	0x901ebf10: read(fd = 0x6, buf = 0x12c7f0, length = 0x800) = 0x294
[+] 	Received interrupt: 0x2
[+] 	0x90226eb8: send(sockfd = 0x4, buf = 0x1251a0, length = 0x303, flags = 0x0) = 0x0
[+] 	Received interrupt: 0x2
[+] 	read() CONTENT: b''
[+] 	0x901ebf10: read(fd = 0x6, buf = 0x12c7f0, length = 0x800) = 0x0
[+] 	Received interrupt: 0x2
[+] 	close(6) = 0
[+] 	0x901ea670: close(fd = 0x6) = 0x0
[+] 	Received interrupt: 0x2
[+] 	0x901ecd30: fcntl(fd = 0x4, cmd = 0x3, arg = 0x90) = 0x802
[+] 	Received interrupt: 0x2
[+] 	0x901ecd30: fcntl(fd = 0x4, cmd = 0x4, arg = 0x2) = 0x0
[+] 	Received interrupt: 0x2
[+] 	0x90226eb8: send(sockfd = 0x4, buf = 0x1251a0, length = 0x303, flags = 0x0) = 0x0
[+] 	Received interrupt: 0x2
[+] 	0x901ecd30: fcntl(fd = 0x4, cmd = 0x3, arg = 0x10) = 0x2
[+] 	Received interrupt: 0x2
[+] 	0x901ecd30: fcntl(fd = 0x4, cmd = 0x4, arg = 0x802) = 0x0
[+] 	Received interrupt: 0x2
[x] 	Syscall ERROR: ql_syscall_shutdown DEBUG: [Errno 107] Transport endpoint is not connected
Traceback (most recent call last):
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/posix.py", line 213, in load_syscall
    retval = syscall_hook(self.ql, *params)
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/syscall/socket.py", line 364, in ql_syscall_shutdown
    sock.shutdown(how)
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/filestruct.py", line 80, in shutdown
    return self.__socket.shutdown(how)
OSError: [Errno 107] Transport endpoint is not connected
Traceback (most recent call last):
  File "tendaac1518_httpd.py", line 100, in <module>
    my_sandbox([fr'{ROOTFS}/bin/httpd'], ROOTFS)
  File "tendaac1518_httpd.py", line 93, in my_sandbox
    ql.run()
  File "/root/.local/lib/python3.8/site-packages/qiling/core.py", line 597, in run
    self.os.run()
  File "/root/.local/lib/python3.8/site-packages/qiling/os/linux/linux.py", line 184, in run
    self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)
  File "/root/.local/lib/python3.8/site-packages/qiling/core.py", line 777, in emu_start
    raise self.internal_exception
  File "/root/.local/lib/python3.8/site-packages/qiling/core_hooks.py", line 127, in wrapper
    return callback(*args, **kwargs)
  File "/root/.local/lib/python3.8/site-packages/qiling/core_hooks.py", line 170, in _hook_intr_cb
    ret = hook.call(ql, intno)
  File "/root/.local/lib/python3.8/site-packages/qiling/core_hooks_types.py", line 25, in call
    return self.callback(ql, *args)
  File "/root/.local/lib/python3.8/site-packages/qiling/os/linux/linux.py", line 138, in hook_syscall
    return self.load_syscall()
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/posix.py", line 231, in load_syscall
    raise e
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/posix.py", line 213, in load_syscall
    retval = syscall_hook(self.ql, *params)
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/syscall/socket.py", line 364, in ql_syscall_shutdown
    sock.shutdown(how)
  File "/root/.local/lib/python3.8/site-packages/qiling/os/posix/filestruct.py", line 80, in shutdown
    return self.__socket.shutdown(how)
OSError: [Errno 107] Transport endpoint is not connected
```
在网上搜索这个错误，然后看到了一篇文章：

[「非阻塞socket」报错 “BlockingIOError: [Errno 11]“ 复现以及分析解决_blockingioerror: [errno 11] resource temporarily u](https://blog.csdn.net/pythontide/article/details/109242386)

![](images/Pasted%20image%2020231024221530.png)

我的简单理解就是在模拟的过程中，因为某种情况，缓冲区的数据已经接受完了但仍然调用`recv()`然后就报错了，博客中作者通过给recv()加入try-except异常机制来解决这个错误。因此我也采用一样的思路，既然缓冲区数据已经读完，这条指令执行不成功应该也没有影响。我修改了qiling的代码，加入了try-except异常捕获机制，修改的代码位置位于qiling/os/posix/filestruct.py:116，修改前只有一个return语句。
```python
# qiling/os/posix/filestruct.py:116
    def recv(self, bufsize: int, flags: int) -> bytes:
        return self.__socket.recv(bufsize, flags)
```

修后的代码如下：
```python
# qiling/os/posix/filestruct.py:116
    def recv(self, bufsize: int, flags: int) -> bytes:
        try:
            return self.__socket.recv(bufsize, flags)
        except BlockingIOError as err:
            print(err)
            return b""
```

#### OSError: \[Errno 107] Transport endpoint is not connected
对于第二个错误，我在这篇文章看了它的说明，`客户端socket 已经关闭的情况，服务器端socket 调用shutdown 则会出现这个错误。`

[linux socket 错误 Transport endpoint is not connected 在 recv shutdown 中的触发时机_failed to reload daemon: transport endpoint is not](https://blog.csdn.net/whatday/article/details/104056667)

于是采用和上面一样的思路，采用try-except捕获异常处理，既然出现错误时套接字已经关闭了，那么这条指令调用不成功也没用什么影响。

具体来说，我修改了qiling的代码，加入了try-except异常捕获机制，修改的代码位置位于qiling/os/posix/filestruct.py:79，修改前只有一条return语句，修改后的代码如下：
```python
# qiling/os/posix/filestruct.py:79
    def shutdown(self, how: int) -> None:
        try:
            return self.__socket.shutdown(how)
        except OSError as err:
            print(err)
            return 0
```

这时再运行刚开始的脚本，通过浏览器访问页面时就不会出现错误崩溃了。

![](images/Pasted%20image%2020231024223049.png)

### 3.2 漏洞验证
#### 漏洞验证
为了验证通过qiling模拟跑起来的程序是否能够触发漏洞，以及修改是否对漏洞触发有影响，我执行了这一步骤：通过一个已知的漏洞PoC进行验证，看程序是否会崩溃。

我选择的PoC如下
```python
import requests

host = 'http://127.0.0.1:8080'
data = ("firewallEn="+'a'*0x500).encode()

session = requests.session()
session.get(host)
res = session.post(url = "http://127.0.0.1:8080/goform/SetFirewallCfg", data=data)
print(res.text)
```

该漏洞位于对"goform/SetFirewallCfg"请求进行解析的函数"formSetFirewallCfg()"中，在49行获取请求数据中的`firewallEn`参数值并将其保存在`src`变量中，随后在53行在未验证字符串大小的情况下，通过`strcpy`危险函数将`src`直接拷贝给了栈上变量`dest`，从而造成栈溢出。

![](images/Pasted%20image%2020231024223736.png)

程序崩溃如下图，提示`Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)`。

![](images/Pasted%20image%2020231025083351.png)

qiling崩溃时会显示上下文信息，可以看到PC值被溢出。

![](images/Pasted%20image%2020231025083736.png)

#### 验证时出现的异常
上面是正常的显示结果，我在刚开始验证的时候溢出字符串太长了，在这个案例中超过了0x520，结果崩溃的时候PC显示在strcpy（libc.so.0 + 0x03e508）崩溃了，且崩溃错误提示`Invalid memory write (UC_ERR_WRITE_UNMAPPED)`，这与我通过Qemu仿真的结果不一致并且刚开始也没用成功启动调试功能导致我以为是qiling仿真存在问题。

![](images/Pasted%20image%2020231025084543.png)

![](images/Pasted%20image%2020231025084608.png)

后来经过研究发现问题出在了栈溢出字符串太长，超出了qiling所映射的栈的范围，strcpy在写的时候就会尝试向栈外没有映射的区域写从而抛出`Invalid memory write`错误，后面调试也是成功调试了，应该是我之前的操作有误，稍后我也会介绍一下我调试的步骤，现在继续来介绍内存写错误问题。

如图所示，通过qiling提供的错误上下文信息可以看到内存写崩溃时涉及到的两个地址为0x7ff3cae0和0x7ff3d000。

![](images/Pasted%20image%2020231025085812.png)

通过看内存映射信息，发现这两个地址位于栈空间，而栈的空间位于0x7ff0d000-0x7ff3d000，可以看到写入的地址r3已经位于栈的边缘了。

![](images/Pasted%20image%2020231025085509.png)

#### 调试
现在我们通过gdb进行调试，查看strcpy调用时刚开始的写入地址。

qiling调试的方法就是在`ql.run()`运行前设置`ql.debugger = True`。

```python
def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    ql.add_fs_mapper(r'/dev/urandom', r'/dev/urandom')

	ql.debugger = True  # open debugger

    ql.run()
```

然后运行后会停住，等待gdb连接其9999端口。

![](images/Pasted%20image%2020231025090640.png)

我们在另一个终端开启`gdb-multiarch`，然后连接，在0xACA84（`strcpy`调用地址）下断点运行。
```bash
gdb-multiarch -q bin/httpd
gdb> target remote :9999
gdb> b *0xACA84
gdb> c
```

![](images/Pasted%20image%2020231025090822.png)

![](images/Pasted%20image%2020231025091042.png)

这个时候程序通过qiling仿真起来，我们执行poc.py程序触发漏洞，稍微等待一会儿gdb就会在我们设置的断点停下。

![](images/Pasted%20image%2020231025091302.png)

可以看到strcpy当前尝试写入的地址为`0x7ff3cae0`，而栈最大地址为`0x7ff3d000`，它们之间的差值为`0x520`。于是我尝试将溢出字符串分别改为`0x520`和`0x51f`来触发漏洞，结果的确如所猜想的那样，前者会尝试向栈外地址写输入从而在调用strcpy时就触发`Invalid memory write`错误，而后者可以正常执行到return语句，pc(0x61616160)值无法解析从而触发`Invalid memory fetch`错误。

```python
# throw Invalid memory write error
data = ("firewallEn="+'a'*0x520).encode()
# throw Invalid memory fetch error
data = ("firewallEn="+'a'*0x51f).encode()
```

### 3.3 模糊测试
在经过前面成功的仿真和漏洞触发验证后，现在就可以尝试开始写模糊测试脚本了。

在恢复快照后运行ql.run()时必须指定起始地址begin，否则qiling会从头重新开始跑。若保存快照时设置的为A地址，则恢复快照后begin也为A地址。




## 4.关于qiling fuzz固件的相关文章
在研究的过程中我收集了一些关于使用qiling对固件进行模糊测试的文章，目前能找到的相关文章的数量还是比较少的。

[VinCSS Blog: [PT007] Simulating and hunting firmware vulnerabilities with Qiling](https://blog.vincss.net/2020/12/pt007-simulating-and-hunting-firmware-vulnerabilities-with-Qiling.html)

[jtsec | Blog | Evaluating IoT firmware through emulation and fuzzing](https://www.jtsec.es/blog-entry/113/evaluating-iot-firmware-through-emulation-and-fuzzing)

[Dynamic analysis of firmware components in IoT devices | Kaspersky ICS CERT](https://ics-cert.kaspersky.com/publications/reports/2022/07/06/dynamic-analysis-of-firmware-components-in-iot-devices/?utm_source=securelist&utm_medium=link&utm_campaign=dynamic-analysis-of-firmware-components-in-iot-devices)

[2020 看雪SDC议题回顾 | 麒麟框架：现代化的逆向分析体验 (kanxue.com)](https://zhuanlan.kanxue.com/article-14181.htm)+

[[Fuzzing] Qiling 框架在 Ubuntu22.04 rootfs下遇到 CPU ISA level 错误的临时解决方案 - 赤道企鹅的博客 | Eqqie's Blog](https://eqqie.cn/index.php/archives/2015)

[Qiling Fuzz实例分析 (qq.com)](https://mp.weixin.qq.com/s/RiPgpROBlwJo9endSJkk_w?ref=www.ctfiot.com)

[D1T3 - Qiling Framework with IDA Pro.pdf (cyberweek.ae)](https://cyberweek.ae/materials/2020/D1T3%20-%20Qiling%20Framework%20with%20IDA%20Pro.pdf)

[使用Qiling分析Dlink DIR-645中的缓冲区溢出(part I) - 先知社区 (aliyun.com)](https://xz.aliyun.com/t/8156#toc-0)

[从零开始的 Boa 框架 Fuzz (seebug.org)](https://paper.seebug.org/2043/)

[bkerler/netgear_telnet: Netgear Enable Telnet (New Crypto) (github.com)](https://github.com/bkerler/netgear_telnet/tree/main)

[Emulate_iot_programs_with_qiling_1 | JiansLife](https://www.jianslife.me/posts/emulate_iot_programs_with_qiling_1/)

## 5.参考链接
