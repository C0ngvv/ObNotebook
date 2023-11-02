
## 仅二进制的模糊测试：一些经常出现的问题
QEMU是 AFL++ 支持的后端之一，用于处理纯二进制目标的检测。在实践中，这意味着，与源代码可用的目标相反，您不会重新编译源代码以获取插桩的二进制文件。相反，AFL++ 使用 QEMU 用户模式仿真的修补版本来执行原始二进制文件，以收集覆盖率信息。

下图说明了使用 QEMU 模式（使用 -Q 标志）进行模糊测试的非常基本的执行：

![](images/Pasted%20image%2020231102093802.png)

使用 QEMU 模式，可以配置不同的方面，以优化模糊测试性能和覆盖率。

然而，从理论到实践有时看起来很乏味，并且经常会提出一些反复出现的问题，例如：

- 我们希望检测插桩哪段代码？
- 模糊器入口点的最佳选择是什么？
- 移动入口点对测试用例的格式意味着什么？
- 我们的测试过程如何从 AFL++ 中提供的高级功能中受益以提高效果？

本文的目的是一起看看我们如何在实际案例中回答这些问题，从基本配置到针对目标优化的设置，这些设置可以重用并应用于其他类似项目。

## 目标
### 一个脆弱的X509解析器
我们选择的示例的灵感来自我们在安全评估中遇到的现实目标（但由于显而易见的原因无法重新分发）。它是一个二进制文件，它需要文件名作为输入，并尝试将相应文件的内容解析为 X509 证书。

它只包含几个基本功能：
- main: main 函数，它以文件为输入，并以此文件为参数调用parse_cert;
- parse_cert: 调用 read_file 并将读取缓冲区作为参数提供给 parse_cert_buf;
- read_file: 打开文件，读取文件并返回其内容;
- parse_cert_buf: 将缓冲区解析为具有 openssl C 库中d2i_X509的 X509 证书，尝试获取 CN 并打印它。

特意的，此目标包含我们希望在模糊测试活动中达到的微不足道的漏洞：parse_cert_buf中基于堆栈的缓冲区溢出：

```c
int parse_cert_buf(const unsigned char *buf, size_t len) {
    X509 *cert;
    char cn[MAX_CN_SIZE];

    cert = d2i_X509(NULL, &buf, len);
    ...
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    strcpy(cn, subj);  // Oops
    printf("Got CN='%s' from certificate\n", cn);
    ...
}
```

也有意在主函数的开头添加了一个虚拟的 init 函数，以模拟初始化阶段，这需要时间并使目标启动缓慢。

## 探索目标
在现实生活中，目标显然不像我们弱的 X509 解析器那么简单。事实上，一个好的纯二进制目标的模糊测试活动总是从逆向工程阶段开始，以：

- 了解目标、它是如何工作的、它如何与环境相互作用等。
- 确定要研究的有趣特征;
- 找到可能被证明是模糊测试的良好目标的函数; 
- 分析调用上下文、结构、用户控制的参数等。 
- 构建一个工具或工具链，以使用适当的参数和模糊输入调用目标函数; 
- 生成一个初始语料库以启动模糊器。

尽管存在一些工具（例如fuzzable）来帮助完成其中一些步骤，但它们通常仍然是模糊测试二进制目标的必需、乏味和手动部分。

由于我们的示例很简单，因此您不必花费太长时间即可找到易受攻击的代码、调用跟踪并确定感兴趣的函数：parse_cert_buf。

```
00000000000013d4 <parse_cert_buf>:
    13d4: 55                    push   rbp
    13d5: 48 89 e5              mov    rbp,rsp
    13d8: 53                    push   rbx
    13d9: 48 83 ec 68           sub    rsp,0x68
...
    1473: 48 89 d6              mov    rsi,rdx
    1476: 48 89 c7              mov    rdi,rax
    1479: e8 92 fc ff ff        call   1110 <strcpy@plt>
...
    14d9: b8 00 00 00 00        mov    eax,0x0
    14de: 48 8b 5d f8           mov    rbx,QWORD PTR [rbp-0x8]
    14e2: c9                    leave
    14e3: c3                    ret
```

## Corpus
### 收集输入
首先，我们需要收集示例输入文件来构建语料库。事实上，AFL++ 文档指出：

> 为了正常运行，模糊测试器需要一个或多个起始文件，其中包含目标应用程序通常预期的输入数据的良好示例。

在我们的例子中，由于目标解析证书，我们只需使用 openssl 生成一个证书：

```
$ openssl req -nodes -new -x509 -keyout key.pem -out cert.pem
```

### 语料库预处理
在使用此语料库之前，我们可以：

- 仅保留导致不同执行路径的输入样本（使用 afl-cmin）; 
- 最小化每个输入样本以保留其不同的执行路径，同时使其大小尽可能小（使用 afl-tmin）。这将使未来的突变更加有效。

我们将这两个步骤合并到一个build_corpus.sh脚本中:

```bash
#!/bin/bash
FUZZ_DIR=`dirname $(realpath -s $0)`
source "$FUZZ_DIR/afl_config.sh"

in_path="$FUZZ_DIR/corpus"
out_path="$corpus_path"

if [ -d "$out_path" ]
then
  echo "$out_path alread exists, aborting"
  exit 1
fi

"$afl_path"/afl-cmin -Q -i "$in_path" -o "$out_path" -- "$target_path" @@

if [ -d "$out_path" ]
then
  cd "$out_path"
  for i in *; do
    "$afl_path"/afl-tmin -Q -i "$i" -o "$i".min -- "$target_path" @@
    rm "$i"
  done
else
  echo "afl-cmin failed, aborting"
fi
```

现在，假设您按照 README.md 中的步骤构建了 AFL++，您可以继续从 step0 目录运行 build_corpus.sh。这将完成语料库最小化步骤，并为后续步骤做好准备。

## Instrumentation
AFL++ 是一个“覆盖率引导”的模糊器，这意味着突变策略将先前执行的代码覆盖率考虑在内，以生成新的输入。要构建覆盖率信息，AFL++-QEMU 需要知道已达到哪些基本块。这是通过检测每个基本块以跟踪它什么时候命中来实现的。

### 默认配置(step0)
通过默认启动 AFL++-QEMU，如[step0]([AFLplusplus-blogpost/step0 at main · airbus-seclab/AFLplusplus-blogpost (github.com)](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step0)) 所示，将检测目标的所有基本块，并且共享库不包含在检测中。

请注意执行速度指示器：您可以密切关注它如何随着我们帖子的每一步而演变。

### 插桩调整(step1)
通常研究需要更改此默认插桩行为。原因可能包括：

- 您有兴趣涵盖主二进制文件导入的库中的所有可能路径; 
- 您希望排除库中已经过安全性测试的特定部分; 
- 插桩一个完整的巨大二进制文件会降低执行速度。

若要查看插桩范围，可以使用以下选项：

- `AFL_INST_LIBS`;
- `AFL_QEMU_INST_RANGES`;
- `AFL_CODE_START`;
- `AFL_CODE_END`.

在我们的示例中，对 parse_cert_buf 进行检测至关重要，对 main 或共享库（如 libssl.so）进行检测则不那么重要。为此，我们只对感兴趣的函数进行检测。这可以通过设置 `AFL_QEMU_INST_RANGES`来实现（参见[step1](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step1)）：

- 以 parse_cert_buf 第一条指令的地址为起点；
- 结束于 parse_cert_buf 最后一条指令的地址。

注意：在我们的例子中，也可以使用 AFL_CODE_START 和 AFL_CODE_END。不过，AFL_QEMU_INST_RANGES 更为灵活，因为它允许指定多个范围进行检测，所以我们更倾向于使用这个环境变量。

这些地址可以手动确定，也可以从 objdump 输出中推导出来：

```bash
## Base address
# The base address at which QEMU loads our binary depends on the target 
# See https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#21-the-start-address
case $(file "$target_path") in
  *"statically linked"*)
    QEMU_BASE_ADDRESS=0
    ;;
  *"32-bit"*)
    QEMU_BASE_ADDRESS=0x40000000
    ;;
  *"64-bit"*)
    QEMU_BASE_ADDRESS=0x4000000000
    ;;
  *) echo "Failed to guess QEMU_BASE_ADDRESS"; exit 1
esac

## Helper functions

function find_func() {
    objdump -t "$target_path" | awk -n /"$1"'$/{print "0x"$1, "0x"$5}'
}
function hex_encode() {
    printf "0x%x" "$1"
}

## Instrumentation

# We only want AFL++ to instrument our target function, not the rest of the
# binary we're fuzzing
# See https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.md#6-partial-instrumentation
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert_buf")
inst_start=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr")))
inst_end=$(hex_encode $(("$inst_start" + "$fuzz_func_size")))
export AFL_QEMU_INST_RANGES="$inst_start-$inst_end"
```

```bash
$ find_func "parse_cert_buf" 
0x00000000000013d4 0x0000000000000110
```

通过启用 AFL++-QEMU 的调试模式 (AFL_DEBUG)，我们可以检查仪器范围是否符合我们的要求：
```
Instrument range: 0x40000013d4-0x40000014e4 (<noname>)
```

从现在起，我们的目标只对感兴趣的部分进行检测，并随时准备进行模糊处理。

## Entrypoint
### 概念和默认行为
进行模糊测试时，AFL++ 会运行目标，直到到达特定地址（AFL 入口点），然后从该地址开始分叉，进行每次迭代。默认情况下，AFL 入口点被设置为目标的入口点（在我们的例子中，目标的 \_start 函数）。

事实上，在默认配置中，AFL++ 会打印以下信息：

```bash
# from the step0 directory 
$ AFL_DEBUG=1 ./fuzz.sh | grep entrypoint 
AFL forkserver entrypoint: 0x40000011a0
```

使用 objdump 对目标程序进行反汇编，可以确认入口点被设置为 \_start 函数的地址：

```bash
# from the step0 directory 
$ objdump -d --start-address=0x11a0 ../src/target | head -n20 
00000000000011a0 <_start>: 
	11a0: 31 ed xor ebp,ebp 
	11a2: 49 89 d1 mov r9,rdx 
	... 
	11b4: 48 8d 3d fa 03 00 00 lea rdi,[rip+0x3fa] # 15b5 <main> 
	11bb: ff 15 1f 2e 00 00 call QWORD PTR [rip+0x2e1f] # 3fe0 <__libc_start_main@GLIBC_2.34> 
	...
```

在这种配置下，每次迭代都会运行整个目标。

### 选择定位(step 2)
在某些情况下（如我们的示例），程序的初始化阶段可能需要时间。由于每次迭代都要执行初始化，因此会直接影响模糊测试的速度。这正是 AFL_ENTRYPOINT 选项要解决的问题。

事实上，可以将 AFL_ENTRYPOINT 设置为相关的自定义值，这样就可以：
- 只运行一次初始化阶段，直至到达 AFL_ENTRYPOINT 地址；
- 在 AFL_ENTRYPOINT 处停止目标机并与模糊器同步；
- 让模糊器捕捉目标的状态，然后在到达 AFL_ENTRYPOINT 地址后继续执行。

这样，在 fork 服务器运行所有迭代之前，初始化阶段只需运行一次，从而加快了模糊测试的速度。

在我们的示例中，选择 AFL_ENTRYPOINT 的定位其实很简单：
- init代码不需要模糊处理；
- init阶段是确定的
- 与模糊处理相关的函数已经确定（parse_cert）。

因此，我们可以将AFL_ENTRYPOINT设置为parse_cert函数的起点（见 [step2](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step2)）：
```bash
# Define a custom AFL++ entrypoint executed later than the default (the binary's # entrypoint) 
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert") 
export AFL_ENTRYPOINT=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr")))
```

在这种配置下，AFL++ 会打印以下信息：
```bash
$ AFL_DEBUG=1 ./fuzz.sh | grep entrypoint 
AFL forkserver entrypoint: 0x40000014e4
```

通过使用 objdump 反汇编 target，我们可以确认这是 parse_cert 的地址：
```
$ objdump -d --start-address=0x14e4 ../src/target | head -n10 
00000000000014e4 <parse_cert>: 
	14e4: 55 push rbp 
	14e5: 48 89 e5 mov rbp,rsp 
	14e8: 48 83 ec 20 sub rsp,0x20
```

### 性能影响
通过运行模糊器，我们可以看到调整 AFL_ENTRYPOINT 的好处：

默认的 AFL_ENTRYPOINT：`exec speed : 18.24/sec (zzzz...)`

调整 AFL_ENTRYPOINT（以跳过init阶段）：`exec speed : 1038/sec`

这说明，AFL_ENTRYPOINT 的选择对于模糊器每秒执行测试次数的最大化至关重要。

在下一节中，我们将看到利用 AFL++ 的另一个特性：持久模式，还可以进一步提高性能。

## Persistence
### 持久模式
#### 环境变量
"持久模式 "是一个允许 AFL++ 避免每次迭代都调用 fork 的功能。相反，当子进程到达某个地址（AFL_QEMU_PERSISTENT_ADDR）时，它会保存子进程的状态，并在到达另一个地址（AFL_QEMU_PERSISTENT_RET）时恢复该状态。

注意： 可以使用 AFL_QEMU_PERSISTENT_RET 代替 AFL_QEMU_PERSISTENT_RETADDR_OFFSET。如果没有设置这些值，AFL++ 将在到达第一个 ret 指令时停止（仅当 AFL_QEMU_PERSISTENT_ADDR 指向函数的起点时，否则必须手动设置该值）。

"恢复 "状态可能指 "恢复寄存器"（AFL_QEMU_PERSISTENT_GPR）和/或 "恢复内存"（AFL_QEMU_PERSISTENT_MEM）。由于恢复内存状态的代价很高，因此只有在必要时才应这样做；在进行模糊测试时，应密切关注稳定性值，以确定是否有必要启用该功能。

即使使用持久模式，AFL++ 仍会不时调用 fork（每 AFL_QEMU_PERSISTENT_CNT 循环一次，默认为 1000）。如果稳定性足够高，增加该值可能会提高性能（最大值为 10000）。

#### 应用于我们的例子
在我们的例子中，可以先将 AFL_QEMU_PERSISTENT_ADDR 设置为与 AFL_ENTRYPOINT 相同的值（parse_cert 函数的地址）。这样，AFL++ 就会将我们的进程恢复到读取输入文件内容之前的状态。

以下是 afl_config.sh 中的相关部分：
```bash
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert")
export AFL_QEMU_PERSISTENT_ADDR=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr"))) 
export AFL_QEMU_PERSISTENT_GPR=1 
export AFL_QEMU_PERSISTENT_CNT=10000
```

在我们的示例中，无需还原内存状态就能保持 100% 的稳定性，因此我们只设置了 AFL_QEMU_PERSISTENT_GPR。我们还将 AFL_QEMU_PERSISTENT_CNT 增加到最大值，因为这不会对稳定性产生负面影响。

您可以直接使用[step3](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step3)文件夹中提供的文件进行测试。您还可以亲自证实 AFL++ 文档中描述的性能提升确实存在：根据我们的测试，每秒迭代次数增加了 10 倍以上！

### 内存模糊处理(step4)
尽管使用了持久模式，但在到达模糊函数之前，我们的目标仍会执行一些不必要的操作，特别是打开和读取模糊器生成的文件内容。相反，我们可以使用 "内存模糊 "跳过这一步，直接从模糊器内存中读取输入案例！

#### Hook
为此，我们必须实现一个 "钩子"。它其实非常简单，源代码就在这个文件中[this file](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/hook/hook.c)：

```c
/*
 * Inspired by https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/qemu_persistent_hook/read_into_rdi.c
 */
#include "hook.h"
#include <string.h>

#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x) - guest_base)

void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base, uint8_t *input_buf, uint32_t input_buf_len) {
  // Make sure we don't overflow the target buffer
  if (input_buf_len > 4096)
    input_buf_len = 4096;

  // Copy the fuzz data to the target's memory
  memcpy(g2h(regs->rdi), input_buf, input_buf_len);

  // Update the length
  regs->rsi = input_buf_len;
}

int afl_persistent_hook_init(void) {
  // 1 for shared memory input (faster), 0 for normal input (you have to use
  // read(), input_buf will be NULL)
  return 1;
}
```

- 我们定义了一个 afl_persistent_hook_init 函数，用于声明是否要使用内存模糊处理；
- 更有趣的是，我们定义了一个 afl_persistent_hook 函数，它可以在每次迭代时，即在到达 AFL_QEMU_PERSISTENT_ADDR 地址之前，覆盖寄存器值和内存。我们所要做的就是覆盖包含要解析的缓冲区的内存，并在正确的寄存器中设置其长度。

注意：您可以通过运行 gdb 并在目标函数的起始位置断开来确定要使用的寄存器，或者直接查看反汇编代码。

该钩子应编译为共享库，AFL++ 将在运行时加载它。

#### 环境变量
要指示 AFL++ 使用我们的钩子，只需将 AFL_QEMU_PERSISTENT_HOOK 设置为.so文件的路径即可：
```
export AFL_QEMU_PERSISTENT_HOOK="$BASEPATH/src/hook/libhook.so"
```

如前所述，我们希望修改 AFL_QEMU_PERSISTENT_ADDR，以便在迭代过程中跳过对 read_file 的调用。这里有两个选项：
- 或者将其设置为 base64_decode 的起始地址。在这种情况下，我们还将对 base64_decode 函数进行模糊测试；
- 或者将其设置在 parse_cert_buf 的起始地址。在这种情况下，将不会对 base64_decode 进行模糊测试。

由于 base64_decode 是由我们不想进行模糊处理的可信外部库（在本例中为 OpenSSL）实现的，因此我们将选择第二个选项。

因此，我们可以将 AFL_QEMU_PERSISTENT_ADDR 移至 parse_cert_buf 的地址：
```bash
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert_buf") 
export AFL_QEMU_PERSISTENT_ADDR=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr")))
```

#### 输入格式
移动 AFL_QEMU_PERSISTENT_ADDR 会对我们的语料库产生影响。事实上，模糊器生成的缓冲区现在直接用于 parse_cert_buf（而不会传递给 base64_decode）。这意味着我们必须重建语料库。在我们的情况下，这很容易：我们只需解码之前语料库中的 base64 文件，并将其保存为原始二进制文件即可。

#### 应用到我们的例子
这种方法的一个特殊之处在于，由于我们不再从文件中读取数据，因此模糊器不再需要在磁盘上创建文件。不过，请记住，我们的目标程序需要从文件中读取数据，否则就会立即退出。由于这个文件的内容不再重要（因为 read_file 不再被调用），我们可以在调用程序前手动创建一个空的占位符。

您可以在[step4 folder](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step4)文件夹中找到这个新设置。

#### 性能影响
总的来说，在我们的测试中，启用持久模式后，性能提高了 10 倍（但在实际应用中，不要总是期望有这样的提升！），而内存挂钩的性能又提高了两倍：`exec speed : 25.6k/sec`

## Grammer-aware mutator(step5)
### 动机
回顾一下我们迄今取得的成就：
- 我们设置了 AFL++，以便使用 QEMU 对纯二进制目标进行模糊测试；
- 我们配置了插桩，使其仅覆盖相关地址；
- 我们调整了 AFL++ 的入口点，并启用了持久模式以节省初始化时间。

在许多情况下，这样的配置与我们稍后将简要介绍的多进程相结合，就足以成功运行一个模糊活动。不过，在本例中，我们决定对处理高度结构化数据格式的目标进行模糊处理。在这种情况下，引入新的方法来改变输入数据可能会很有趣。

事实上，AFL++ 的另一个可调方面是生成和突变逻辑。AFL++ 内置支持一系列简单（但非常有效）的突变：
- 随机位翻转
- 随机字节翻转
- 算术
- 等等。

在大多数情况下，这些突变足以对代码进行模糊处理。有些数据格式有内部限制，会导致样本因不符合这些限制而被过早剔除。例如，ASN.1（我们示例中使用的格式）就是这种情况：在不考虑这些限制的情况下生成突变，可能会导致大多数样本立即被目标视为无效而被丢弃，而不会增加任何覆盖率。这意味着模糊测试需要一定的时间才能收敛到相关的生成案例。

为了解决这类问题，AFL++ 允许用户提供自己的自定义突变器，以引导模糊器生成更合适的输入。正如官方文档中详细说明的那样，只要自定义突变器实现了所需的 API 函数，就可以将其插入 AFL++。

### 实现
在 AFL++ 中实现语法感知突变器有几种选择，其中之一是 AFL++ 项目的语法突变器部分[Grammar Mutator part of the AFL++ project](https://github.com/AFLplusplus/Grammar-Mutator)。不过，由于它不支持 ASN.1，我们转而依赖处理 ASN.1 的libprotobuf。

我们从官方文档[custom_mutators.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/custom_mutators.md)和现有骨架[P1umer/AFLplusplus-protobuf-mutator](https://github.com/P1umer/AFLplusplus-protobuf-mutator)中汲取灵感，在 AFL++ 和我们的自定义突变器之间构建了 "粘合剂"。

结果存在于[custom_mutator.cpp](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator/custom_mutator.cpp)，并实现了 AFL++ API 中的以下函数：

- afl_custom_init 用于初始化我们的自定义突变器；
- afl_custom_fuzz 使用我们的 protobuf mutator 对输入数据进行变异；
- afl_custom_post_process 对变异后的数据进行后处理，以确保我们的目标接收到格式正确的输入；
- afl_custom_deinit 用于清理所有内容。

### 输入格式
事实上，afl_custom_post_process 函数扮演了一个重要角色：我们的自定义突变器基于 libprotobuf，因此需要将 protobuf 数据作为输入。然而，我们的目标机只能解析 ASN.1 数据，因此我们需要将数据从 protobuf 转换为 ASN.1。值得庆幸的是，protobuf mutator 已经在 x509_certificate::X509CertificateToDER 中实现了这一功能。

整个过程概述如下：

![](images/Pasted%20image%2020231102104952.png)

和以前一样，我们需要调整语料库中的文件格式，以便与我们的模糊处理工具保持一致。这次，我们需要将 ASN.1 DER 文件转换为 protobuf。为此，我们执行了一个自定义脚本（[asn1_to_protobuf.py](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator/asn1_to_protobuf.py)），由本步骤的[build_corpus.sh](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step4/build_corpus.sh)运行一次。

### 环境变量
这样，剩下的工作就是指示 AFL++ 使用我们自定义的突变器了。为此，我们只需将 AFL_CUSTOM_MUTATOR_LIBRARY 设置为 .so 文件的路径：
```bash
export AFL_CUSTOM_MUTATOR_LIBRARY="$BASEPATH/libmutator.so"
```

我们还禁用了 AFL++ 执行的所有默认突变和修剪：
```bash
export AFL_DISABLE_TRIM=1 
export AFL_CUSTOM_MUTATOR_ONLY=1
```

### 应用于我们的示例
您可以在[step5 folder](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step5)文件夹中找到这个新设置。

### 影响
这一次，不是要提高性能，而是要深入路径。在我们的示例中，目标非常小，因此很难衡量这种影响。不过，通常可以通过比较覆盖率和检查是否使用自定义突变器到达了新的分支来实现。

不过，您不必在使用自定义突变器和使用默认 AFL++ 突变器之间做出选择：您可以通过运行多个模糊器实例来获得两全其美的效果，下一步我们将讨论这一点。

## Multiprocessing ([step6](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step6))
在这一步中，我们将所有内容整合在一起，以开展实际的模糊测试活动。事实上，在实际测试中，您不会只在一个内核/线程/机器上进行模糊测试。值得庆幸的是，AFL++ 可以并行运行多个实例。

不过，正如[the documentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores)所述，同时运行过多实例并不总是有用的：
> 在同一台机器上，由于 AFL++ 工作方式的设计原因，有用的 CPU 内核/线程数是有上限的，使用更多的 CPU 内核/线程，整体性能反而会下降。该值取决于目标，限制在每台机器 32 到 64 个内核之间。

值得注意的是，即使在达到这一极限之前，性能的提升也并不成正比（内核数量翻倍并不能使每秒执行次数翻倍）：同步进程需要额外的开销。

### 不同的配置、突变器和时间表
在运行多个模糊器实例时，可以通过并行使用各种策略和配置来优化覆盖率。由于我们的目的不是照搬 AFL++ 的官方文档，因此请参考[this section](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores)，其中介绍了如何在模糊测试时使用多个内核。

不过，由于该页面主要针对有源代码的模糊测试目标，因此需要对某些方面进行调整，以便进行纯二进制模糊测试。

### 仅二进制特点
在对有源代码的目标进行模糊测试时，许多功能（如 ASAN、UBSAN、CFISAN、COMPCOV）需要使用特定选项重新编译目标。尽管在处理二进制目标时，重新编译并不是一个选项，但 QEMU 还是提供了其中的一些功能（如[here](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_binary-only_targets.md#qemu-mode)所记录的）。

例如，AFL_USE_QASAN 允许使用 LD_PRELOAD 自动注入库，以便在 QEMU 中使用 ASAN。同样，AFL_COMPCOV_LEVEL 允许在 QEMU 中使用 COMPCOV，而无需重新编译目标机。

### 多设备设置
对于规模较大的模糊测试活动，您可以使用多台主机，每台主机运行多个模糊器进程。这种设置其实相当简单，[official documentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#d-using-multiple-machines-for-fuzzing)中也有详细介绍。为了简化和可重复性，我们在这篇文章中没有使用多台机器。

### 应用于我们的例子
从这篇博文开始，输入格式和目标函数发生了变化。下表汇总了这些变化：

|Configuration|Targeted function|Expected input format|
|---|---|---|
|Default entrypoint|`main()`|`base64(ASN.1)`|
|Custom entrypoint|`main()`|`base64(ASN.1)`|
|In-memory fuzzing|`parse_cert_buf()`|`ASN.1 / DER`|
|Custom mutator|`parse_cert_buf()`|`protobuf`->`ASN.1`|

在这一步中，我们将运行一个带有自定义突变器的实例和几个不带突变器的实例。因此，我们需要一个 ASN.1 格式的语料库（corpus_unique）和一个 protobuf 格式的语料库（corpus_protobuf_unique），并使用不同的输出目录。

[step6 folder](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/step6)文件夹中提供了此类多语料库设置的示例。请注意，与其他步骤不同的是，大多数有趣的改动都在 fuzz.sh 文件中，而不是 afl_config.sh。

## 评估模糊活动的前景
启动营销活动后，您可能需要对其进行监控、评估其效率并调查其结果。这不在本篇文章的讨论范围之内，官方文档提供了各种细节，我们不打算在此赘述。不过，为了给您一个概念，我们将快速介绍其中的一些问题。

### 监测活动
AFL++ 提供以下工具来监控运行中实例的状态：
- afl-whatsup，用于显示后台运行的模糊器实例的状态：
```
$ afl-whatsup -s output 
Summary stats 
============= 
	Fuzzers alive : 4 
	Total run time : 4 minutes, 0 seconds 
	Total execs : 1 millions, 849 thousands 
	Cumulative speed : 30829 execs/sec 
	Average speed : 7707 execs/sec 
	Pending items : 0 faves, 0 total 
	Pending per fuzzer : 0 faves, 0 total (on average) 
	Crashes saved : 3 
	Cycles without finds : 204/26/1066/264 
	Time without finds : 1 minutes, 26 seconds
```

- afl-plot，可以绘制特定实例的指标随时间的变化情况：
```
$ afl-plot output/afl-main /tmp/plot
```

![](images/Pasted%20image%2020231102110204.png)

### 测量覆盖范率
检查覆盖范围则是另一回事，对于仅二进制目标而言有各种特殊性。这不在本篇文章的讨论范围之内，但你可以在官方文档[official documentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#g-checking-the-coverage-of-the-fuzzing)中找到有趣的资源。

在我们的 step6 文件夹中，一个典型的命令如下：

```
$ afl-showmap -Q -C -i "$output_path"/afl-main/queue -o afl-main.cov -- "$target_path" /tmp/.afl_fake_input
```

### 调查崩溃和超时
AFL++一旦识别出崩溃或挂起，就会将触发崩溃或挂起的输入保存到输出目录下的专用文件夹中，以便您重现崩溃或挂起。

了解这些结果的有用工具包括:

- afl-tmin 获取重现碰撞的最小测试案例；
- Lighthouse 用于探索特定案例的覆盖范围；
- Valgrind 用于调查内存问题；
- 等等！

此外，对于自定义突变器发现的情况，输入将是 protobuf 格式，而这种格式不容易在目标机上直接重放。为此，我们开发了一个简单的程序，可以将 protobuf 转换回 ASN.1 格式（参见 [protobuf_to_der.cpp](https://github.com/airbus-seclab/AFLplusplus-blogpost/tree/main/src/mutator/protobuf_to_der.cpp)）。

## 我们目前的进展
我们在这篇文章中的目的是强调我们的方法，解释 AFL++ 的概念，并提供模糊纯二进制目标的骨架。这促使我们根据我们的目标和自身经验做出选择，而这些选择在其他情况下可能并不适用。特别是，其他语法突变器的实现可能更简单（例如，如果语法突变器支持正确的语法）。

不过，通过配置内存中的持久性、调整定制的语法感知突变以及实施多进程，我们实现了执行速度和覆盖范围都令人感兴趣的模糊测试活动。

显然，这仅仅是故事的开始：运行模糊测试活动和分析结果本身也会带来一系列新的问题和乐趣！

## 链接
原文链接：[Advanced binary fuzzing using AFL++-QEMU and libprotobuf: a practical case of grammar-aware in-memory persistent fuzzing](https://airbus-seclab.github.io/AFLplusplus-blogpost/)
