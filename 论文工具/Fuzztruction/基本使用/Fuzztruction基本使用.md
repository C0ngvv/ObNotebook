## 安装启动
```
# Clone the repository
git clone --recurse-submodules https://github.com/fuzztruction/fuzztruction.git
# 拉取docker镜像，pull 7-8G，解压后40G
sudo ./env/pull-prebuilt.sh
# 启动，创建容器
sudo USE_PREBUILT=1 ./env/start.sh
# 再次运行，进入容器
sudo USE_PREBUILT=1 ./env/start.sh
# 删除容器
sudo ./env/stop.sh
```

## 组件
### Scheduler
- 协调Generator和Consumer之间的互动
- 管理模糊 fuzzing campaign，组织fuzzing loop
- 维护队列，每个实体由Generator种子输入和应用在生成器上的变异组成，代表一个测试用例
- 实现位于`scheduler`目录下

### Generator
- 可以看出目标程序的种子生成器，生成Consumer的输入
- 通过向生成器注入故障来间接地突变输入
- 识别并变异Generator用来产生其输出的数据操作
- 需要一个能产生与模糊处理目标所期望的输入格式相匹配的输出的程序
- 实现在`generator` 目录下，由两个组件组成Compiler Pass和Agent

#### Compiler Pass
- Pass使用patch points 对目标进行插桩
- 由于patch points功能实现不稳定，对LLVM打了实验性补丁，可在[llvm](https://github.com/fuzztruction/fuzztruction-llvm) 库下找到
- patch points的位置被记录在编译后的二进制的一个单独section，与解析这个section相关的代码可以在`lib/llvm-stackmap-rs` 中找到，也发布在[llvm_stackmap - crates.io:](https://crates.io/crates/llvm_stackmap)
- 模糊测试时，Scheduler从patch points集合中选择一个目标，并将决策传递给agent（负责对给定的patch point 应用desired变异）

#### Agent
- 实现位于`generator/agent` 
- 使用自定义的编译器pass 编译，运行在generator应用上下文
- 主要任务是实现forkserver和与scheduler通信
- 基于scheduler通过共享内存和消息队列传递的指令，agent使用JIT引擎变异generator

### Consumer
- Consumer是模糊测试的目标，消耗由Generator生成的输入
- 使用AFL++的编译器Pass编译Consumer应用，用于记录覆盖率反馈，来指导Generator的变异

## Docker容器环境介绍
用户名为`user` 并具有无密码的`sudo` 权限

| Container Path            | Host Path | Note |
| ------------------------- | --------- | ---- |
| `/home/user/fuzztruction` |           | pre-built中的fuzztruction环境目录 |
| `/home/user/shared`       | 主机上fuzztrction项目目录         | 用于和主机交换数据     |

## Building Fuzztruction
使用`./env/start.sh` 返回容器shell后会自动触发build进程，因此环境里已经是构建好的。这部分修改代码后想要重新build程序的情况。

Build Fuzztruction只需要在`/home/user/fuzztruction` 目录下调用`cargo build` 命令就可以了，它会build所有组件。最让人感兴趣的组件是这些：
| Artifacts                                           | Description                                                                                                                       |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `./generator/pass/fuzztruction-source-llvm-pass.so` | LLVM Pass用来对Generator应用插入patch points。pass位置记录在`/etc/ld.so.conf.d/fuzztruction.conf` 中；                            |
| `./generator/pass/fuzztruction-source-clang-fast`   | 编译器wrapper用来编译Generator应用，它使用自定义的编译器Pass，链接目标和agent，向generator的main里注入到agent的init方法的函数调用 |
| `./target/debug/libgenerator_agent.so`              | 被注入到generator应用的agent                                                                                                      |
| `./target/debug/fuzztruction`                       | 代表真实模糊器的fuzztruction二进制                                                                                                 |

## Demo：使用Fuzztruction对一个目标进行模糊测试
这里使用`libpng` 作为案例，`libpng` 相对较小且没有外部依赖。

### 1. 构建目标
即获取构建`libpng` ，这里使用的是pre-build版本的docker环境，里面已经构建好了，这一步可以跳过。

构建方法是切换到`fuzztruction-experiments/comparison-with-state-of-the-art/binaries/` 目录然后执行`./build.sh libpng` ，它会拉去源文件并根据定义在`libpng/config.sh`中的步骤开始build。

### 2. 测试目标
使用下面命令可以测试目标是否工作。每个目标都是用YAML配置文件定义的，这些文件位于配置目录中，是构建自己配置的一个好起点，`pngtopng-pngtopng.yml`文件有大量的文档。
```
sudo ./target/debug/fuzztruction fuzztruction-experiments/comparison-with-state-of-the-art/configurations/pngtopng_pngtopng/pngtopng-pngtopng.yml  --purge --show-output benchmark -i 100
```

![](images/Pasted%20image%2020230403110557.png)

### 3. 故障排除
如果模糊器终止时出现错误，有一些方法可以帮助调试。
- 给`fuzztruction` 传递`--show-output` 可以观察到Generator和Consumer的 stdout/stderr，如果它们不是用来互相传递或读取数据
- 在YAML配置中`sink` 的`env` 部分设置AFL_DEBUG可以获得一个关于Consumer的更详细的输出
- 使用与配置文件中相同的标志来执行生成器和消费者可能会发现用于执行应用程序的命令行中的任何错误。在使用LD_PRELOAD的情况下，仔细检查提供的路径。

### 4. 运行模糊器
执行下面命令来启动模糊测试
```
sudo ./target/debug/fuzztruction ./fuzztruction-experiments/comparison-with-state-of-the-art/configurations/pngtopng_pngtopng/pngtopng-pngtopng.yml fuzz -j 10 -t 10m
```

它会在10个核心上启动模糊测试，超时时间为10分钟。模糊器产生的输出被存储在目标配置文件中`work-directory` 属性定义的目录中。对于这个案例`pngtopng`，默认位置是`/tmp/pngtopng-pngtopng`。

如果工作目录已经存在，必须将`--purge` 作为参数传递给`fuzztruction`，以允许它重新运行。该标志必须在子命令之前传递，即在`fuzz`或`benchmark`前面。

![](images/Pasted%20image%2020230403113430.png)

### 5. 联合Fuzztruction和AFL++
为了与 Fuzztruction 同时运行 AFL++，可以使用`aflpp` 子命令来生成 AFL++ 工作器，这些工作器会在运行期间用 Fuzztruction 发现的输入进行补给。假设Fuzztruction是用上面的命令执行的，那么只要执行下面命令就可以生成10个AFL++进程，终止时间是10min。
```
sudo ./target/debug/fuzztruction ./fuzztruction-experiments/comparison-with-state-of-the-art/configurations/pngtopng_pngtopng/pngtopng-pngtopng.yml aflpp -j 10 -t 10m
```

Fuzztruction和AFL++发现的输入会定期同步到工作目录中的`interesting` 文件夹中。如果AFL++应该独立执行，但基于相同的`.yml`配置文件，可以使用`--suffix`参数为生成的模糊器的工作目录添加一个后缀。

![](images/Pasted%20image%2020230403113523.png)

### 6. 计算覆盖率
在模糊运行结束后，`tracer`子命令允许检索在模糊过程中发现的所有有趣输入的覆盖基本块的列表。这些追踪被存储在工作目录下的`traces` 子目录中。每个追踪都包含一个zlib压缩的JSON对象，其中包含所有在执行过程中行使的基本块的地址（按执行顺序）。此外，还提供了元数据，将地址映射到它们所在的实际ELF文件中。

位于.`/target/debug/coverage`的`coverage`工具可以用来进一步处理收集的数据。你需要把包含Fuzztruction创建的工作目录的顶层目录传递给它（例如，在前面的例子中是/tmp）。执行`./target/debug/coverage /tmp` 将生成一个`.csv`文件，将时间映射到所覆盖的基本块的数量，以及一个`.json `文件，将时间戳映射到所发现的基本块地址集。这两个文件都位于特定模糊测试运行的工作目录中。

### 相关文件
`pngtopng-pngtopng.yml` 文件内容如下
```yml
# Directory where all fuzzing data is stored. It should be located in the /tmp directory
# since file system operations considerably slow down Fuzztruction.
# You should consider resizing/tmp and back it by addition swap since the directory
# can grow quite large.
work-directory: "/tmp/pngtopng_pngtopng"
# Inputs passed to the generator. For applications not consuming any data, this must be some file; thus Fuzztruction stops
# to complain.
input-directory: "./inputs_ft"
# IDs of the user `user` (retrieved via `id`). They are used as the target ids for dropping privileges for child processes.
jail-uid: 606400022
jail-gid: 606400022
timeout: 50ms

# The generator configuration.
source:
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/ft/libpng/contrib/examples/pngtopng"
    # @@: Path to the input file.
    # $$: Path to the output file.
    arguments: ["@@", "$$"]
    # Type of input: file, stdin, none
    input-type: file
    # Type of output: file, stdout
    output-type: file
    log-stdout: false
    log-stderr: false

# The consumer configuration.
sink:
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/afl/libpng/contrib/examples/pngtopng"
    arguments: ["@@", "/dev/null"]
    input-type: file
    output-type: file
    log-stdout: false
    log-stderr: false
    # Whether to add unstable (inputs with varying coverage) to the queue.
    allow-unstable-sink: true

# AFL++ configuration (optional)
afl++:
    # Inputs used by AFL++ to fuzz the consumer.
    input-dir: "./inputs_other"

# SYMCC configuration (optional)
symcc:
    # Custom environment variables for the target. It can also be used for the source, sink, afl++, and vanilla sections.
    # This is mostly  used to set LD_PRELOAD; thus the loader loads the instrumented libraries instead of the ones installed
    # in the system's search path. Please see other `YAML` files for examples,
    env:
        - NONE: "None"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/symcc/libpng/contrib/examples/pngtopng"
    # SYMCC needs a custom afl++ binary, thus we need a separate config entry here.
    afl-bin-env:
        - NONE: "None"
    afl-bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/afl_symcc/libpng/contrib/examples/pngtopng"

# Vanilla binary (uninstrumented), used for coverage computation and fuzzing via WEIZZ.
vanilla:
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/vanilla/libpng/contrib/examples/pngtopng"
    
```

`fuzztruction` 帮助
```
Fuzztruction 1.0
Moritz Schloegel <moritz.schloegel@rub.de>

USAGE:
    fuzztruction [OPTIONS] <config> <SUBCOMMAND>

ARGS:
    <config>    Path to the configuration file specifing the generator and consumer of the
                fuzzing campaign.

OPTIONS:
    -h, --help
            Print help information

        --log-level <trace, debug, info, warn, error, off>
            Log verbosity (alternative to --verbosity) [default: debug]

        --purge
            Purge any data from previous runs. Must be provided if the workdir exists

        --show-output
            Show stdout and stderr of the generator and the consumer. This becomes handy for
            debugging not working configurations

        --suffix <suffix>
            Suffix appended to the workdir path provided via the config file
            (i.e., <WORKDIR>-<SUFFIX>)

    -v, --verbosity
            Sets the level of verbosity (alternative to --log-level)

    -V, --version
            Print version information

SUBCOMMANDS:
    aflpp               Use AFL++ for fuzzing the consumer application. This mode provides 
					    flags to combine AFL++ with SYMCC or WEIZZ. If Fuzztruction (fuzz 
					    mode) is running using the same config as for the aflpp mode, AFL++ 
					    is periodically reseeded with inputs found by Fuzztruction.
    benchmark
    dump-stackmap       Dump the LLVM stackmap (e.g., locations and sizes)
    fuzz
    help                Print this message or the help of the given subcommand(s)
    test-patchpoints    Test the patchpoints of the source application (for debugging)
    tracer              Run DynamoRIO-based tracer to generate basic block traces for each
                            insteresting input found.
    valgrind
```




