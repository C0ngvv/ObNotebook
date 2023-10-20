启动模拟，Qiling()参数中加入`verbose=QL_VERBOSE.DEBUG`可以显示更详细的信息。
```python
from qiling import *
path = r"examples/rootfs/arm_linux/bin/arm_hello".split()
rootfs = r"examples/rootfs/arm_linux/"
ql = Qiling(path, rootfs)
ql.run()
```

## 基本使用方法
### 初始化
```
ql = Qiling()
```

可以设置多个参数选项进行配置，对于二进制仿真的 Qiling初始化基本选项有：

| Name     | Type            | Description                                                                                                        |
| -------- | --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `argv`   | `Sequence[str]` | a sequence of command line arguments to emulate                                                                    |
| `rootfs` | `str`           | the emulated filesystem root directory. all paths accessed by the emulated program will be based on this directory |
|`env`(optional) |`MutableMapping[AnyStr, AnyStr]` | a dictionary of environment variables available for the emualted program |

常见的 Qiling 初始化选项：

| Name                     | Type         | Description                                                                                                                                        |
| ------------------------ | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verbose` (optional)     | `QL_VERBOSE` | sets Qiling logging verbosity level (default: `QL_VERBOSE.DEFAULT`). for more details see [print section](https://docs.qiling.io/en/latest/print/) |
| `profile` (optional)     | `str`        | path to profile file holding additional settings. for more details see [profile section](https://docs.qiling.io/en/latest/profile/)                |
| `console` (optional)     | `bool`       | when set to `False`, disables Qiling logging entirely. this is equivalent to setting `verbose=QL_VERBOSE.DISABLED`                                 |
| `multithread` (optional) | `bool`       | indicates whether the target should be emulated as a multi-threaded program                                                                        |
|`libcache` (optional) |`bool` | indicates whether libraries should be loaded from cache. this saves libraries parsing and relocating time on consequent runs. currently available only for Windows

还有针对shellcode的选项，这里不再列举，可从[Qiling Framework Documentation](https://docs.qiling.io/en/latest/howto/)查看

### 配置
可用选项：

| Options                                      | Description                                                                                    |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `ql.fs_mapper ("tobe_mapped","actual_path")` | 将 qiling 文件或目录中的主机文件或目录映射到实际文件夹，例如，ql.fs_mapper('/etc','/real_etc') |
| `ql.debug_stop = False`                      | 默认为False。缺失posix系统调用或api后停止                                                      |
| `ql.debugger = None`                         | 远程调试器。请参阅[here](https://docs.qiling.io/en/latest/debugger/)                           |
| `ql.verbose = 1`                  |   从1到n，详情请参阅[print section](https://docs.qiling.io/en/latest/print/)部分     |

### 运行
要启动二进制执行，只需调用`ql.run()`。但在某些情况下，例如部分执行，ql.run()还提供了 4 个额外选项，以实现更精细的控制。
```
ql.run(begin, end, timeout, count)
```

## Log Printing
log输出
```
ql.log.info('Hello from Qiling Framework!')
```

### verbose
Qiling的log输出看可以配置不同的等级，默认设置为`logging.INFO`。

| Verbosity Level       | Desciprtion                                                                         |
| --------------------- | ----------------------------------------------------------------------------------- |
| `QL_VERBOSE.DISABLED` | logging is disabled entirely                                                        |
| `QL_VERBOSE.OFF`      | logging is restricted to warnings, errors and critical entries                      |
| `QL_VERBOSE.DEFAULT`  | info verbosity                                                                      |
| `QL_VERBOSE.DEBUG`    | debug verbosity; increased verbosity                                                |
| `QL_VERBOSE.DISASM`   | emit disassembly for every emulated instruction; this implies debug verbosity       |
| `QL_VERBOSE.DUMP`     | emit cpu context along with disassembled instructions; this implies debug verbosity |

在初始化时可用通过`verbose`参数设置，在模拟过程中也可以动态配置该属性。
```
ql = Qiling([r'/bin/ls'], r'examples/rootfs/x86_linux', verbose=QL_VERBOSE.DEBUG)
```

### ql.filter
此外，还可以使用`ql.filter`通过正则表达式对日志进行过滤。
```
if __name__ == "__main__": 
	ql = Qiling([r'examples/rootfs/arm_linux/bin/arm_hello'], r'examples/rootfs/arm_linux') 
	# show only log entries that start with "open" 
	ql.filter = '^open' ql.run()
```

## Hook
### ql.hook_address()
hook一个地址，当执行到指定地址时就激活回调函数。
```
ql.hook_address(callback.Callable, address.int)
```

例
```
from qiling import Qiling def stop(ql: Qiling) -> None: ql.log.info('killer switch found, stopping') ql.emu_stop() ql = Qiling([r'examples/rootfs/x86_windows/bin/wannacry.bin'], r'examples/rootfs/x86_windows') # have 'stop' called when execution reaches 0x40819a ql.hook_address(stop, 0x40819a) ql.run()
```
