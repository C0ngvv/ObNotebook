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

## Target
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

## Memory配置
第二个需要提供给avatar的信息是指定内存布局，avatar会跟踪所有内存范围，并将产生的内存映射结合所有范围推送到各个目标。





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

