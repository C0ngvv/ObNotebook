Qiling是一个功能强大的二进制模拟框架，还可以用于fuzz固件等二进制程序，因此学习一下它的用法是必要的。这里的内容大部分都来自于官方文档（[Qiling Framework Documentation](https://docs.qiling.io/en/latest/)），是对其主要内容的整理和汇总，学习的过程中应该跟着[看雪文章](https://bbs.kanxue.com/thread-268989.htm)做一下[Shielder-QilingLab](https://www.shielder.com/blog/2021/07/qilinglab-release/)，做完之后对Qiling的大致使用方法就掌握了，相关链接已放在末尾。

## 基本使用方法
启动模拟，Qiling()参数中加入`verbose=QL_VERBOSE.DEBUG`可以显示更详细的信息。
```python
from qiling import *
path = r"examples/rootfs/arm_linux/bin/arm_hello".split()
rootfs = r"examples/rootfs/arm_linux/"
ql = Qiling(path, rootfs)
ql.run()
```

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
```python
ql.run(begin, end, timeout, count)

# 停止模拟
ql.emu_stop()
```

## Log Printing
log输出
```python
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
```python
# 寄存器取值赋值
eax = ql.arch.regs.eax
ql.arch.regs.eax = 0xFF
# 跨架构寄存器，仅限于pc和sp
ql.arch.regs.arch_pc 
ql.arch.regs.arch_sp
ql.arch.regs.arch_pc = 0xFF
ql.arch.regs.arch_sp = 0xFF
# 获取寄存器位数
ql.arch.reg_bits("rax")
```

## Memory
### 内存映射
在访问内存之前，必须对其进行映射。映射方法在指定位置绑定一个连续的内存区域，并设置其访问保护位。可以提供一个字符串标签，以便在映射信息表（参见：get_map_info）中轻松识别。
```
ql.mem.map(addr: int, size: int, perms: int = UC_PROT_ALL, info: Optional[str] = None) -> None
```

- `addr`；需要映射的基地址，应按页面粒度，需要对齐内存偏移和地址以进行映射。
- `size`：映射大小（以字节为单位），必须是页面大小的倍数
- `perms`：保护位图，定义此内存范围是否可读、可写和/或可执行
- `info`：为映射范围设置字符串标签，以方便识别（可选）

unmap方法可在指定位置回收内存区域，unmap功能不局限于完整内存区域，也可用于部分范围。
```
ql.mem.unmap(addr: int, size: int) -> None
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

### 栈操作
```python
# 出栈入栈
value = ql.arch.stack_pop()
ql.arch.stack_push(value)

# 读|写距离栈顶指定偏移位置而不修改sp，偏移offset可为正、负、0
value = ql.arch.stack_read(offset)
ql.arch.stack_write(offset, value)
```

## Hook
### ql.hook_address()
hook一个地址，当执行到指定地址时就激活回调函数，执行完后还是继续从指定地址运行程序，因此pc寄存器值未作修改。
```
ql.hook_address(callback.Callable, address.int)
```

例子
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

### ql.hook_block()
hook基本块代码
```python
def ql_hook_block_disasm(ql, address, size): 
	ql.log.debug("\n[+] Tracing basic block at 0x%x" % (address)) ql.hook_block(ql_hook_block_disasm)
```

### ql.hook_intno()
hook中断数来激活一个自定义函数
```python
ql.hook_intno(hook_syscall, 0x80)
```

### ql.hook_mem_read()
拦截位置在begin和end之间的内存读，在值被读取之前激活回调函数。
- 如果end没有指定，仅仅当begin处地址读时被拦截
- 如果begin和end都没有指定，则当作为设置为所有内存
- 回调函数value参数值是无用的，总是为0
- 回调函数可能在它被读之前修改内存中的值

```python
from unicorn.unicorn_const import UC_MEM_READ

def mem_read(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
	# only read accesses are expected here
	assert access == UC_MEM_READ
	ql.log.debug(f'intercepted a memory read from {address:#x}')

stack_lbound = ql.arch.regs.arch_sp 
stack_ubound = ql.arch.regs.arch_sp - 0x1000
ql.hook_mem_read(mem_read, begin=stack_ubound, end=stack_lbound)
```

### ql.hook_mem_write()
拦截位置在begin和end之间的内存写，在值被写入之前激活回调函数。
- 如果end没有指定，仅仅当begin处地址读时被拦截
- 如果begin和end都没有指定，则当作为设置为所有内存

```python
from unicorn.unicorn_const import UC_MEM_WRITE

def mem_write(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
	# only write accesses are expected here 
	assert access == UC_MEM_WRITE
	ql.log.debug(f'intercepted a memory write to {address:#x} (value = {value:#x})')

trigger_address = 0xdecaf000
ql.hook_mem_write(mem_write, trigger_address)
```

### ql.clear_hooks()
清除所有的hook
```python
ql.clear_hooks()
```

## Hijack
### Hijacking program standard streams
Qiling可以劫持程序的标准流（stdin、stdout 和 stderr），并用自定义实现来取代它们。下面的示例展示了如何接管stdin 并为其输入我们自己的内容。

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

下面的示例将虚拟路径 /dev/urandom 映射到一个用户定义的文件对象，该对象允许对交互进行更精细的控制。请注意，映射对象继承了QlFsMappedObject。
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
## Snapshot
Qiling可用设置和恢复快照。

```python
# Qiling状态的保存和恢复
ql_all = ql.save() 
ql.restore(ql_all)
ql.save(snapshot="snapshot.bin")
ql.restore(snapshot="snapshot.bin")
# 附加选项
ql.save(mem=True, reg=True, fd=True, cpu_ctx=False)

# 当前文件描述符状态的保存和恢复
all_fd = ql.fd.save() 
ql.fd.restore(all_fd)

# CPU状态的保存和恢复
all_registers_context = ql.arch.regs.context_save()
ql.arch.regs.context_restore(all_registers_context)

# 内存状态的保存和恢复
all_mem = ql.mem.save() 
ql.mem.restore(all_mem)

# 寄存器的保存、设置和恢复
all_registers = ql.arch.regs.save() 
all_registers["eip"] = 0xaabbccdd
ql.arch.regs.restore(all_registers)
```

案例
```python
from qiling.const import QL_VERBOSE 

def dump(ql, *args, **kw): 
	ql.save(reg=False, cpu_context=True, snapshot="/tmp/snapshot.bin") 
	ql.emu_stop() 

# 通过hook运行到0x1094后激活回调函数dump，通过调用ql.save()保存当前的模拟状态到文件snapshot.bin中，并停止模拟
ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEFAULT) 
X64BASE = int(ql.profile.get("OS64", "load_address"), 16) 
ql.hook_address(dump, X64BASE + 0x1094) 
ql.run() 

# 通过调用ql.restore恢复模拟状态，并可以设置从begin位置开始模拟而非前面hook的0x1094，跳过某些代码继续执行
ql = Qiling(["../examples/rootfs/x8664_linux/bin/sleep_hello"], "../examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG) 
X64BASE = int(ql.profile.get("OS64", "load_address"), 16) ql.restore(snapshot="/tmp/snapshot.bin") 
begin_point = X64BASE + 0x109e 
end_point = X64BASE + 0x10bc 
ql.run(begin = begin_point, end = end_point)
```

## Pack and Unpack
Qiling有一些内置函数来处理内存的打包和解包，但如果需要更大的灵活性，可用使用python的`struct`库。

```python
# 数字代表位数，没有数字标明的取决于架构位数，小端，表示unsigned "Q, I, H"
ql.pack()
ql.pack64()
ql.pack32()
ql.pack16()

ql.unpack()
ql.upack64()
ql.unpack32()
ql.unpack16()

# 加上s表示signed "q, i, h"
ql.packs()
ql.pack64s()
ql.pack32s()
ql.pack16s()

ql.unpacks()
ql.upack64s()
ql.unpack32s()
ql.unpack16s()
```

## Profile
使用自定义用户配置文件覆盖Qiling框架的默认配置文件值。
```python
from qiling import * 
from qiling.const import QL_VERBOSE.DEBUG 
def my_sandbox(path, rootfs): 
	ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG, profile= "netgear.ql") 
	ql.add_fs_mapper("/proc", "/proc") 
	ql.run() 

if __name__ == "__main__": 
	my_sandbox(["rootfs/netgear_r6220/bin/mini_httpd","-d","/www","-r","NETGEAR R6220","-c","**.cgi","-t","300"], "rootfs/netgear_r6220")
```

其中netgear.ql内容为：
```
[MIPS] 
mmap_address = 0x7f7ee000 
log_dir = qlog 
log_split = True
```

不同操作系统的默认配置：
- Windows: [qiling/pofiles/windows.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/windows.ql)
- Linux: [qiling/pofiles/linux.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/linux.ql)
- MacOS: [qiling/pofiles/macos.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/macos.ql)
- UEFI: [qiling/pofiles/uefi.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/uefi.ql)
- FreeBSD: [qiling/pofiles/freebsd.ql](https://github.com/qilingframework/qiling/blob/dev/qiling/profiles/freebsd.ql)

## 参考链接
[Hook - Qiling Framework Documentation](https://docs.qiling.io/en/latest/hook/)

[[原创]11个小挑战，Qiling Framework 入门上手跟练-软件逆向-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-268989.htm)

[Shielder - QilingLab – Release](https://www.shielder.com/blog/2021/07/qilinglab-release/)
