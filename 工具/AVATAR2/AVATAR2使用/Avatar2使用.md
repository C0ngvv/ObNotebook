Avatar2提供了手册书：[avatar2/handbook/0x01_intro.md at main · avatartwo/avatar2 · GitHub](https://github.com/avatartwo/avatar2/blob/main/handbook/0x01_intro.md)
## 安装
命令行pip3直接安装

```python
pip3 install avatar2
```

## Hello World案例
在[avatar2/handbook/0x01_intro.md](https://github.com/avatartwo/avatar2/blob/main/handbook/0x01_intro.md)提供了Hello案例，其流程是用gdbserver运行程序作为终端，然后为avatar2添加GDBTarget目标，然后init()进行目标和终端的连接，通过write_memory()写入shellcode，作用是输出Hello World，执行cont()进行继续执行，从而输出Hello World。

```python
import os
import subprocess

from avatar2 import *


filename = 'a.out'
GDB_PORT = 1234          

# This is a bare minimum elf-file, gracefully compiled from 
# https://github.com/abraithwaite/teensy
tiny_elf = (b'\x7f\x45\x4c\x46\x02\x01\x01\x00\xb3\x2a\x31\xc0\xff\xc0\xcd\x80'
            b'\x02\x00\x3e\x00\x01\x00\x00\x00\x08\x00\x40\x00\x00\x00\x00\x00'
            b'\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00'
            b'\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00'
            b'\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x20\x00\x00\x00\x00\x00')
            
            

# Hello world shellcode
shellcode = (b'\x68\x72\x6c\x64\x21\x48\xb8\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x50'
             b'\x48\x89\xef\x48\x89\xe6\x6a\x0c\x5a\x6a\x01\x58\x0f\x05')
          

# Save our executable to disk
with open(filename, 'wb') as f:
    f.write(tiny_elf)
os.chmod(filename, 0o744)

# Create the avatar instance and specify the architecture for this analysis
avatar = Avatar(arch=archs.x86.X86_64)

# Create the endpoint: a gdbserver connected to our tiny ELF file
gdbserver = subprocess.Popen('gdbserver --once 127.0.0.1:%d a.out' % GDB_PORT, shell=True)

# Create the corresponding target, using the GDBTarget backend
target = avatar.add_target(GDBTarget, gdb_port=GDB_PORT)

# Initialize the target. 
# This usually connects the target to the endpoint
target.init()

# Now it is possible to interact with the target.
# For example, we can insert our shellcode at the current point of execution
target.write_memory(target.read_register('pc'), len(shellcode),
                    shellcode, raw=True)

# We can now resume the execution in our target
# You should see hello world printed on your screen! :)
target.cont()

# Clean up!
os.remove(filename)
avatar.shutdown()****
```

执行结果如图所示

![](images/Pasted%20image%2020230808153008.png)

## handbook
### Target
编写Avatar2脚本首先需要创建target，下面是案例，实例化一个QemuTarget对象并赋予一个名字qemu1，若不指定名字它会自动生成一个名字。可以通过变量或赋予的名字与target进行交互。

```python
from avatar2 import *
avatar = Avatar()
qemu = avatar.add_target(QemuTarget, name='qemu1')
avatar.targets['qemu1'] == qemu

>>> qemu = avatar.add_target(QemuTarget)
>>> qemu.name
'QemuTarget0'
```

avatar2提供了5中Target:`GDBTarget`, `OpenOCDTarget`, `JLinkTarget`, `QemuTarget`, `PandaTarget`。不同Target支持的参数配置信息详看[avatar2/handbook/0x02_targets.md](https://github.com/avatartwo/avatar2/blob/main/handbook/0x02_targets.md)

### Memory配置
第二个需要提供给avatar的信息是指定内存布局，avatar会跟踪所有内存范围，并将产生的内存映射结合所有范围推送到各个目标。

定义内存范围的方法非常简单，如下面一行代码可在地址 0x40000000 处创建一个大小为 0x1000 的基本内存区域：

```python
dummy_range = avatar.add_memory_range(0x40000000, 0x1000)
```

在创建过程中还可以指定各种关键字，其中一些可能只有特定类别的目标才能使用。

|Keyword|Description|
|---|---|
|name|An optional name for the memory range|
|permissions|The permissions in textual representation. Default: 'rwx'|
|file|Path to a file which holds the initial contents for the memory|
|forwarded|Whether memory accesses to the range needs to be forwarded to a specific target|
|forwarded_to|If forwarding is enabled, reference to the target that will handle the memory accesses|
|emulate|Enable avatars peripheral emulation for the given memory range|

转发规则本身是在配置内存范围时使用 forwarded 和 forwarded_to 参数设置的。假设我们正在 QEMU 中分析一个包含内存映射外设的物理设备。内存范围配置示例如下：

```python
mmio = avatar.add_memory_range(0x4000000, 0x10000, name='mmio',
                               permissions='rw-'
                               forwarded=True, forwarded_to=phys_device)
ram  = avatar.add_memory_range(0x2000000, 0x1000000, name='ram',
                               permissions='rw-')
rom  = avatar.add_memory_range(0x0800000, 0x1000000, name='rom',
                               file='./firmware.bin',
                               permissions='r-x')
```

也可以指定QEMU仿真外设和用户自定义外设，详细见[avatar2/handbook/0x03_memory.md](https://github.com/avatartwo/avatar2/blob/main/handbook/0x03_memory.md)

### 执行
在确定了targets和内存布局之后，Avatar² 的实际分析部分就可以开始了，我们将其称为执行阶段。为了告诉 Avatar² 设置阶段已经完成，可以开始实际执行，首先必须对目标进行初始化。

```python
from avatar2 import *

avatar = Avatar()

# Target setup
[...]

# Memory setup
[...]

# Initialize all targets and prepare for execution
avatar.init_targets()
```

在执行阶段，Avatar² 可以与每个目标交互，控制其执行或操作其内存或寄存器值。

#### 控制目标执行
Avatar² 可以通过使用一组与传统调试器非常相似的功能来控制目标的执行。特别是，所有目标都支持继续、步进和停止执行的基本功能。此外，还可以设置断点和观察点，只要底层目标支持这些功能。

但与传统调试器相比，Avatar² 不会在目标执行时暂停，因为分析者可能希望设置涉及并行执行的复杂协调方案，因此，target会提供一个 wait() 方法，强制 Avatar 脚本等待目标停止执行。

```python
# Get a target which we initialized before
qemu = avatar.targets['QemuTarget0']

# Set a breakpoint
bkpt = qemu.set_breakpoint(0x800e34)

# Continue execution
qemu.cont()

# Before doing anything else, wait for the breakpoint to be hit
qemu.wait()

# Remove the breakpoint
qemu.remove_breakpoint(bkpt)

# Step one instruction
qemu.step()
```

#### 控制目标寄存器
Avatar 可以非常方便地检查和修改目标的寄存器状态：

```python
# Get the content of a register
r0 = qemu.regs.r0

# Set the content of a register
qemu.regs.r0 = 0x41414141
```

在背后下，这将调用 read_register 和 write_register 函数，当然也可以直接调用这两个函数。

```python

# Get the content of a register
r0 = qemu.read_register("r0")

# Set the content of a register
qemu.write_register("r0", 0x41414141)

# Shorter aliases to the exact same functions above
r0 = qemu.rr("r0")
qemu.wr("r0", 0x41414141)
```

#### 控制目标内存
与目标的寄存器状态类似，获取或修改目标的内存内容也是经常需要的，就像读取或写入寄存器一样简单：

```python
# read 4 bytes from addres 0x20000000
qemu.read_memory(0x20000000, 4)

# write 4 bytes to address 0x20000000
qemu.write_memory(0x20000000, 4, 0xdeadbeef)

# aliases
qemu.rm(0x20000000, 4)
qemu.wm(0x20000000, 4, 0xdeadbeef)
```

#### 在目标之间传输执行状态
Avatar² 的一个更有趣的功能是可以在执行过程中在不同目标之间传输状态，以便成功协调。请看下面的示例，其中包括目标设置、内存布局规范以及执行（和状态）从一个目标转移到另一个目标：

```python
from avatar2 import *

sample = 'firmware.bin'
openocd_conf = 'nucleo-l152re.cfg'

# Create avatar instance with custom output directory
avatar = Avatar(output_directory='/tmp/myavatar')

# Add first target
qemu = avatar.add_target(QemuTarget, 
                          gdb_executable="arm-none-eabi-gdb",
                          firmware=sample, cpu_model="cortex-m3",
                          executable="targets/qemu/arm-softmmu/qemu-system-")

# Add the second target
nucleo = avatar.add_target(OpenOCDTarget,
                           gdb_executable="arm-none-eabi-gdb", 
                           openocd_script=openocd_conf)

# Set up custom gdb ports to avoid collisions
qemu.gdb_port = 1234
nucleo.gdb_port = 1235

# Specify first memory range
rom  = avatar.add_memory_range(0x08000000, 0x1000000, name='rom', 
                                   file=sample)
# Specify second memory range
ram  = avatar.add_memory_range(0x20000000, 0x14000, name='ram')

# Initialize Targets
avatar.init_targets()

# Execute on the nucleo up to a specific address
nucleo.set_breakpoint(0x800B570)
nucleo.cont()
nucleo.wait()

# Transfer the state over to qemu
avatar.transfer_state(nucleo, qemu, sync_regs=True, synced_ranges=[ram])

# Continue execution on qemu
qemu.cont()
```

### Watchmen
Avatar² 允许用户在协调过程中挂钩各种事件。这些钩子是用户定义的回调，允许在相应事件发生之前或之后更改或检查分析状态。添加这种钩子的接口如下，第一个参数是要挂钩的事件，第二个参数指定回调函数是在事件处理之前还是之后执行，第三个参数是要执行的回调函数的引用。

```python
from avatar2 import *

def my_callback(avatar, *args, **kwargs):
    print("StateTransfer occured!")

avatar = Avatar()
avatar.watchmen.add_watchmen('StateTransfer', 'after', my_callback)
```

目前，avatar² 支持挂钩以下事件：

|event-name|trigger|additional vars|
|---|---|---|
|StateTransfer|Transfering the state from one target to another|from_target, to_target, sync_regs, synced_ranges|
|BreakpointHit|A breakpoint is reached|BreakpointMessage|
|UpdateState|A target changes its state|UpdateStateMessage|
|RemoteMemoryRead|A forwarded memory read is happening|RemoteMemoryReadMessage|
|RemoteMemoryWrite|A forwarded memory write is happening|RemoteMemoryWriteMessage|
|AvatarGetStatus|The current status of avatar is requested|-|

### 插件
avatar² 的另一个重要功能是其插件系统,插件可以修改或增强avatar或不同目标对象的功能。这样，avatar² 本身的核心部分就很简单，而复杂的功能则可以按需启用或添加。启用插件非常简单：

```python
from avatar2 import *

avatar = Avatar()
avatar.load_plugin('myPlugin')
```

下面，我们将介绍与 avatar² 结合使用的几个典型插件。

#### Orchestrator
最基本的插件之一是Orchestrator。在普通的 avatar² 脚本中，执行计划必须纯粹按顺序指定，而Orchestrator则允许自动执行。从本质上讲，只需指定一组转换和用于执行的第一个目标。

```python
from avatar2 import *

avatar = Avatar()
avatar.load_plugin('orchestrator')

# Target and memory memory map definition
[...]

# Specify the starting target for the orchestration
avatar.start_target = target1

# Add transition from target_1 to target_2 as soon target_1 hits 0x8000b504
avatar.add_transition(0x800B504, target_1, target_2, sync_regs=True, 
                      synced_ranges=[ram])

# Add a 2nd transition from target_1 to target_2 at 0x800b570 and 
# mark it as the end for the automated orchestration
avatar.add_transition(0x800B570, target_2, target_1, sync_regs=True,
                      synced_ranges=[ram], stop=True)

# Begin the orchestration
avatar.start_orchestration()
```

#### Disassembler
反汇编器插件的作用可以用来反汇编机器代码，这在交互式使用 avatar² 时尤其有用。它使用 capstone 作为反汇编后端，并为每个注册到 avatar 对象的目标添加两个函数：disassemble() 和 disassemble_pretty()。第一个函数返回一个 capstone 指令列表，第二个函数返回一个包含反汇编内容的人可读字符串。

默认情况下，这两个函数都会使用 avatar² 架构描述中的可用信息，尝试在目标指令指针位置反汇编一条指令。这一行为可受以下命名参数的影响：

|Argument|Meaning|
|---|--:|
|addr|The address to start disassembling|
|insns|The number of instructions to be disassembled|
|arch|The architecture, as passed to capstone|
|mode|The disassemble mode, as passed to capstone|
#### GDB Core Dumper
GDB 目标可创建内核转储文件，随后可将其加载到调试器中进行手动动态分析。

```python
import os
import subprocess

from avatar2 import *

GDB_PORT = 1234          

avatar = Avatar(arch=archs.x86.X86_64)
gdbserver = subprocess.Popen('gdbserver --once 127.0.0.1:%d /usr/bin/ls' % GDB_PORT, shell=True)
target = avatar.add_target(GDBTarget, gdb_port=GDB_PORT)
target.init()

avatar.load_plugin('gdb_core_dumper')

target.step()

# Save core file to output directory
target.dump_core()

# Save core file to custom location
target.dump_core("/tmp/core.1")
```

## 案例：Nucleo-L152RE
在电路板初始化后，将物理设备的状态传输到仿真器中。

```python
from os.path import abspath
from time import sleep

from avatar2 import *

# Change to control whether the state transfer should be explicit or implicit
USE_ORCHESTRATION = 0


def main():

    # Configure the location of various files
    firmware = abspath('./firmware.bin')

    openocd_config = abspath('./nucleo-l152re.cfg')

    # Initiate the avatar-object
    avatar = Avatar(arch=ARM_CORTEX_M3, output_directory='/tmp/avatar')

    # Create the target-objects
    nucleo = avatar.add_target(OpenOCDTarget, openocd_script=openocd_config)

    qemu = avatar.add_target(QemuTarget, gdb_port=1236)

    # Define the various memory ranges and store references to them
    rom  = avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
    ram  = avatar.add_memory_range(0x20000000, 0x14000)
    mmio = avatar.add_memory_range(0x40000000, 0x1000000,
                                   forwarded=True, forwarded_to=nucleo)

    # Initialize the targets
    avatar.init_targets()

    if not USE_ORCHESTRATION:
        # This branch shows explicit state transferring using avatar

        # 1) Set the breakpoint on the physical device and execute up to there
        nucleo.set_breakpoint(0x8005104)
        nucleo.cont()
        nucleo.wait()

        # 2) Transfer the state from the physical device to the emulator
        avatar.transfer_state(nucleo, qemu, synced_ranges=[ram])

        print("State transfer finished, emulator $pc is: 0x%x" % qemu.regs.pc)
    else:
        # This shows implicit state transferring using the orchestration plugin

        # 1) Load the plugin
        avatar.load_plugin('orchestrator')

        # 2) Specify the first target of the analysis
        avatar.start_target = nucleo

        # 3) Configure transitions
        #    Here, only one transition is defined. Note that 'stop=True' forces
        #    the orchestration to stop once the transition has occurred.
        avatar.add_transition(0x8005104, nucleo, qemu, synced_ranges=[ram],
                              stop=True)

        # 4) Start the orchestration!
        avatar.start_orchestration()

        print("State transfer finished, emulator $pc is: 0x%x" % qemu.regs.pc)

    # Continue execution in the emulator.
    # Due due to the forwarded mmio, output on the serial port of the physical
    # device (/dev/ttyACMx) can be observed, although solely the emulator
    # is executing.
    qemu.cont()

    # Further analysis could go here:
    # import IPython; IPython.embed()

    # Let this example run for a bit before shutting down avatar cleanly
    sleep(5)
    avatar.shutdown()


if __name__ == '__main__':
    main()
```

关于此案例和其他案例信息见：[avatartwo/avatar2-examples: Examples demonstrating the usage of avatar²](https://github.com/avatartwo/avatar2-examples)

## 其他
### gdbserver
在Hello World案例中，启动命令为`gdbserver --once 127.0.0.1:1234 a.out`。gdbserver的用法如下：

>gdbserver is a program that allows you to run GDB on a different machine than the one which is running the program being debugged.
>
>To use a TCP connection, you could say:
               target> gdbserver host:2345 emacs foo.txt
       This tells gdbserver to debug emacs with an argument of foo.txt. The
       "host:2345" argument means that we are expecting to see a TCP
       connection from "host" to local TCP port 2345.

`--once`参数的用法如下,在连接到第一个GDB session后就停止监听其它的连接。

>--once
           By default, gdbserver keeps the listening TCP port open, so that
           additional connections are possible.  However, if you start
           "gdbserver" with the --once option, it will stop listening for any
           further connection attempts after connecting to the first GDB
           session.

