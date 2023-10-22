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

