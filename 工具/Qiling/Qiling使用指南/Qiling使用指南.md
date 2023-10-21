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
```python
if __name__ == "__main__": 
	ql = Qiling([r'examples/rootfs/arm_linux/bin/arm_hello'], r'examples/rootfs/arm_linux') 
	# show only log entries that start with "open" 
	ql.filter = '^open' ql.run()
```

## Register
```
eax = ql.arch.regs.eax
ql.arch.regs.eax = 0xFF
ql.arch.regs.arch_pc 
ql.arch.regs.arch_sp
```

## Memory
### 内存映射
**在访问内存之前，必须对其进行映射**。映射方法在指定位置绑定一个连续的内存区域，并设置其访问保护位。可以提供一个字符串标签，以便在映射信息表（参见：get_map_info）中轻松识别。
```
ql.mem.map(addr: int, size: int, perms: int = UC_PROT_ALL, info: Optional[str] = None) -> None
```

- `addr`；需要映射的基地址，应按页面粒度，需要对齐内存偏移和地址以进行映射。
- `size`：映射大小（以字节为单位），必须是页面大小的倍数
- `perms`：保护位图，定义此内存范围是否可读、可写和/或可执行
- `info`：为映射范围设置字符串标签，以方便识别（可选）

unmap方法可在指定位置回收内存区域，unmap功能不局限于完整内存区域，也可用于部分范围。
```
ql.mem.unmap(addr: int, size: int) -> None:
```

显示所有映射的区域
```python
for info_line in self.ql.mem.get_formatted_mapinfo():
	self.ql.log.error(info_line)
```
### 内存访问
```python
# 读写
ql.mem.read(address, size)
ql.mem.write(address, data)
#写入整数时需要pack
ql.mem.write(0x1337, ql.pack16(1337))  # or struct.pack("H",1337))

# 读写字符串
ql.mem.string(address)
ql.mem.string(address, "stringwith")

# 搜索匹配
address = ql.mem.search(b"\xFF\xFE\xFD\xFC\xFB\xFA")
address = ql.mem.search(b"\xFF\xFE\xFD\xFC\xFB\xFA", begin= 0x1000, end= 0x2000)
```

## Hook
### ql.hook_address()
hook一个地址，当执行到指定地址时就激活回调函数。
```
ql.hook_address(callback.Callable, address.int)
```

例
```python
from qiling import Qiling
def stop(ql: Qiling) -> None: 
	ql.log.info('killer switch found, stopping') 
	ql.emu_stop() 
	
ql = Qiling([r'examples/rootfs/x86_windows/bin/wannacry.bin'], r'examples/rootfs/x86_windows') 
# have 'stop' called when execution reaches 0x40819a 
ql.hook_address(stop, 0x40819a) 
ql.run()
```

### ql.hook_code()
hook所有指令，注册的回调将在每条汇编指令执行前被调用
```python
from capstone import Cs
def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
	buf = ql.mem.read(address, size)
	for insn in md.disasm(buf, address):
		ql.log.debug(f':: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}')

ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)
```

## Hijack
### Hijacking program standard streams
Qiling可以劫持程序的标准流（stdin、stdout 和 stderr），并用自定义实现来取代它们。下面的示例展示了如何接管stdin 并为其输入我们自己的内容。仿真程序稍后将使用这些内容。

```python
# 劫持程序stdin并输入指定内容
ql.os.stdin = pipe.SimpleInStream(0)
ql.os.stdin.write(b'Ea5yR3versing\n')
```
### Hijacking VFS objects
虽然 rootfs 中包含的文件和文件夹都是静态的，但仿真程序可能需要访问虚拟文件系统对象，如 udev、procfs、sysfs等。为了弥补这一差距，Qiling 允许将虚拟路径绑定到主机系统上的现有文件或自定义文件对象。

下面的示例将虚拟路径 /dev/urandom 映射到主机系统上现有的 /dev/urandom 文件。当仿真程序访问 /dev/random 时，将访问映射的文件。
```python
ql.add_fs_mapper(r'/dev/urandom', r'/dev/urandom')
```

下面的示例将虚拟路径 /dev/random 映射到一个用户定义的文件对象，该对象允许对交互进行更精细的控制。请注意，映射对象继承了QlFsMappedObject。
```python
from qiling.os.mapper import QlFsMappedObject
class FakeUrandom(QlFsMappedObject):
	def read(self, size: int) -> bytes:
		return b"\x04"
	def fstat(self) -> int:
		return -1
	def close(self) -> int:
		return 0

ql.add_fs_mapper(r'/dev/urandom', FakeUrandom())
```

另一种用途是磁盘模拟。通常情况下，程序希望直接访问磁盘，你可以利用 fs mapper 来模拟磁盘。
```
from qiling.os.disk import QlDisk
emu_path = 0x80
emu_disk = QlDisk(r'rootfs/8086_dos/petya/out_1M.raw', emu_path)
ql.add_fs_mapper(emu_path, emu_disk)
```

QlDisk 对象实际上继承自 QlFsMappedObejct，并实现了磁盘操作逻辑，如磁盘柱面、磁头、扇区和逻辑块地址。out_1M.raw 是原始磁盘映像，0x80 是 BIOS 和 DOS 中的磁盘驱动器索引。对于 Linux 和 Windows，驱动器索引可能分别是"/dev/sda "或"\.\PHYSICALDRIVE0"。
### Hijack POSIX system calls
POSIX系统调用可能被挂钩，允许用户修改参数、更改返回值或完全替换其功能。系统调用可以通过名称或编号挂钩，并在一个或多个阶段被拦截：
- `QL_INTERCEPT.CALL`：当指定的系统调用即将被调用时；可用于完全替换系统调用功能
- `QL_INTERCEPT.ENTER`：可用于篡改系统调用参数值
- `QL_INTERCEPT.EXIT`：可用于篡改返回值

```python
from qiling.const import QL_INTERCEPT
def my_syscall_write(ql: Qiling, fd: int, buf: int, count: int) -> int:
	data = ql.mem.read(buf, count)
	fobj = ql.os.fd[fd]
	if hasattr(fobj, 'write'):
		fobj.write(data)

ql.os.set_syscall('write', my_syscall_write, QL_INTERCEPT.CALL)
```

### Hijacking OS API(POSIX)
与系统调用一样，POSIX libc函数也可以类似的方式挂钩，允许用户控制其功能。
```python
from qiling.const import QL_INTERCEPT 
from qiling.os.const import STRING

def my_puts(ql: Qiling):
	params = ql.os.resolve_fcall_params({'s': STRING})
	s = params['s']
	print(s)
	return len(s)

ql.os.set_api('puts', my_puts, QL_INTERCEPT.CALL)
```

## 参考链接
[Hook - Qiling Framework Documentation](https://docs.qiling.io/en/latest/hook/)

[[原创]11个小挑战，Qiling Framework 入门上手跟练-软件逆向-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-268989.htm)
