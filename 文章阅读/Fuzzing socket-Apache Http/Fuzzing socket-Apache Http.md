# Fuzzing sockets: Apache HTTP, Part 1: Mutations
原文链接：[Fuzzing sockets: Apache HTTP, Part 1: Mutations | GitHub Security Lab](https://securitylab.github.com/research/fuzzing-apache-1/)

在之前关于套接字的博客文章中，我介绍了如何对 FTP 服务器进行模糊处理，并详细说明了如何对 FreeRDP 进行模糊处理。在 "套接字测试 "系列的第三部分，也是最后一部分，我将重点介绍 HTTP 协议，更具体地说，我将以 Apache HTTP 服务器 (https://httpd.apache.org/) 为目标。

作为最流行的网络服务器之一，Apache HTTP 服务器无需任何介绍。Apache HTTP 是最早的 HTTP 服务器之一，其开发可追溯到 1995 年。截至 2021 年 1 月，它的市场份额为 26%，是互联网上使用第二多的网络服务器，目前运行在 300 000 000多台服务器上，仅略微落后于 Nginx（31%）。

我将分三部分详细介绍我的 Apache 模糊研究。在第一集中，我将简要介绍 Apache HTTP 的工作原理，并向大家介绍自定义突变器以及如何将其有效应用于 HTTP 协议。

## Custom mutators
与纯粹的随机输入生成不同，突变模糊会对现有输入进行微小改动，这些改动可能会保持输入的有效性，但也会产生新的行为。这就是我们所说的 "突变器"。

默认情况下，AFL模糊器实现了基本的突变器，如位翻转、字节增减、简单算术或块拼接。这些突变器总体效果不错，尤其是在二进制格式中，但在应用于基于文本的格式（如 HTTP）时，它们的成功率有限。因此，我决定创建一些额外的突变器，专门用于对 HTTP 协议进行模糊测试。您可以在以下链接中找到代码[following link](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/tree/main/Custom%20mutators)。

在这次练习中，我重点研究的一些变异策略包括：

- 部件交换：交换两个不同请求的部件
	- 行交换：交换两个不同 HTTP 请求的行
	- 词语交换：交换两个不同 HTTP 请求的字词
- 字符集暴力破解：对某些字符集进行暴力破解
	- 1 字节暴力破解： 0x00 - 0xFF
	- 2 个字节 强制：0x0000 - 0xFFFF
	- 3 个字母的暴力破解\[a-z]{3}
	- 4 位数暴力破解：\[0-9]{4}
	- 3 个字母和数字 bruteforce: (\[a-z]\[0-9){3}
	- 3 字节/4 字节字符串 bruteforce：使用输入文件中所有 3/4 字节字符串进行 bruteforce。

![](images/Pasted%20image%2020231102145444.png)

![](images/Pasted%20image%2020231102145841.png)

您可以在[here](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Custom%20mutators/Mutators_aux.c)找到使用这些自定义突变器所需的附加函数。

### Coverage comparative
我们希望在使用自定义突变器进行长期模糊测试之前，能够确定该突变器是否有效。

有鉴于此，我使用自定义突变器的不同组合进行了一系列模糊测试。我的目标是找到能在24小时内提供更高代码覆盖率的突变器组合。

起始覆盖率如下（仅使用原始输入语料）：

- Lines: **30.5%**
- Functions: **40.7%**

这些是每个突变体组合 24 小时后的结果（所有测试都在 AFL_DISABLE_TRIM=1 和 -s 123 的条件下进行）：

![](images/Pasted%20image%2020231102150140.png)

此处未列出的突变体显示出更差的结果，因此未被列入考虑范围。如您所见，行混合 + AFL HAVOC 是制胜的组合。

![](images/Pasted%20image%2020231102150238.png)

之后，我又进行了第二次测试，增加了启用的 Apache Mods 数量。行混合 + HAVOC 测试再次取得了成功。

![](images/Pasted%20image%2020231102150339.png)

虽然这是一个成功的组合，但这并不意味着我只使用了这个自定义突变器。在整个 Apache HTTP 模糊测试过程中，我使用了所有可用的自定义突变器，因为我的目标是获得最高的代码覆盖率。在这种情况下，突变器的效率就变得不那么重要了。

### Custom grammar
另一种方法是使用基于语法的突变器。除了使用自定义突变器外，我还使用最近添加到 AFL++ 中的一个工具自定义了一个语法，用于对 HTTP 进行模糊测试：[Grammar-Mutator](https://github.com/AFLplusplus/Grammar-Mutator)。

使用Grammar-Mutator非常简单：

```
make GRAMMAR_FILE=grammars/http.json
./grammar_generator-http 100 100 ./seeds ./trees
```

然后

```
export AFL_CUSTOM_MUTATOR_LIBRARY=./libgrammarmutator-http.so
export AFL_CUSTOM_MUTATOR_ONLY=1
afl-fuzz …
```

在我的案例中，我创建了一个简化的 HTTP 语法规范[a simplified HTTP grammar specification](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Custom%20Grammars/http.json)：

![](images/Pasted%20image%2020231102150648.png)

我包含了最常见的 HTTP 动词（GET、HEAD、PUT......）。在这个语法中，我还使用了单个 1 字节字符串，然后在后面的阶段，我使用[Radamsa](https://gitlab.com/akihe/radamsa)增加了这些字符串的长度。Radamsa 是另一种通用模糊器，最近作为自定义突变库被添加到 AFL++ 中。同样，我在这里省略了大部分附加字符串，而是选择将它们包含在字典中。

## Apache configuration
默认情况下，Apache HTTP 服务器是通过编辑`[install_path]/conf`文件夹中的文本文件进行配置的。主配置文件通常称为 httpd.conf，每行包含一条指令。此外，还可以使用 Include 指令添加其他配置文件，并使用通配符包含多个配置文件。反斜杠"（\）"可用作一行的最后一个字符，表示该指令继续到下一行，反斜杠和行尾之间不得有其他字符或空白。

### Modules, modules and more modules
Apache 采用模块化架构。您可以启用或禁用模块，添加或删除网络服务器功能。除了 Apache HTTP 服务器默认捆绑的模块外，还有大量第三方模块提供扩展功能。

要在构建 Apache 时启用特定模块，可在构建的配置步骤中使用--enable-\[mod]标志：

```
./configure --enable-[mod]
```

其中，mod 是我们要包含在构建中的模块名称。

我采用的是渐进式方法：我首先启用了一小部分模块（--enable-mods-static=few），在达到稳定的模糊测试工作流程后，我又启用了一个新模块，并再次测试了模糊测试的稳定性。此外，我还使用--enable-\[mod]=static和--enable-static-support标志对Apache模块进行静态链接，从而显著提高了模糊测试速度。

完成构建步骤后，我们可以定义这些模块在什么情况下发挥作用。为此，我修改了 httpd.conf 文件，并将每个模块链接到不同的唯一位置（目录或文件）。这样，我们就有了指向不同 Apache 模块的不同服务器路径。

![](images/Pasted%20image%2020231102151013.png)

![](images/Pasted%20image%2020231102151047.png)

为了让模糊器的工作更轻松，我的 htdocs 文件夹中包含的大多数文件的文件名长度都是 1/2 字节。这样，AFL++ 就能轻松猜出有效的 URL 请求。

例如：

- `GET /a HTTP 1.0`
- `POST /b HTTP 1.1`
- `HEAD /c HTTP 1.1`

在进行模糊测试时，我尝试启用尽可能多的 Apache 模块，目的是检测模块间的并发错误。

### Bigger dictionaries, please
我在尝试模糊 Apache 时发现的一个限制是，AFL 能够以确定性方式管理的字典条目的最大数量限制为 200。

问题在于，我在httpd.conf中加入的每一个新模块及其相应位置，都需要添加相应的字典条目。例如，如果我在 "mod_crypto "位置添加了一个新的 "scripts "文件夹，我也需要在字典中添加一个新的 scripts 字符串。此外，有些模块（例如 webdav）还需要很多新的 HTTP 动词（PROPFIND、PROPPATCH 等）。

出于这个原因，并考虑到更大的字典在其他情况下也很有用，我向 AFL++ 项目提交了一个[pull](https://github.com/AFLplusplus/AFLplusplus/pull/519)请求，以添加这一功能。

这将产生一个新的 AFL_MAX_DET_EXTRAS 环境变量，允许我们设置以确定方式使用的字典条目的最大数量。你可以在[here](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Dictionaries/http_request_fuzzer.dict.txt)找到我使用的字典之一。

在本系列的第二部分，我们将演示一种处理文件系统系统调用的更有效方法，并深入探讨 "文件监控器 "的概念。

## Code changes
### MPM fuzzing
Apache HTTP 服务器 2.0 将其模块化设计扩展到网络服务器的最基本功能。该服务器随附了一系列多处理模块（MPM），这些模块负责绑定到机器上的网络端口、接受请求并派遣子模块处理请求。有关 Apache MPM 的更多信息，请访问 https://httpd.apache.org/docs/2.4/mpm.html。

在基于 Unix 的操作系统中，Apache HTTP服务器默认配置 MPM 事件，不过我们可以通过 --with-mpm=\[choice] 配置标志选择要使用的 MPM 版本。每个MPM模块在多线程和多处理方面都有不同的功能。因此，我们的模糊处理方法将根据所使用的 MPM 配置而有所不同。

我对这两种配置进行了模糊处理：

- Event MPM (multithread and multiprocess)
- Prefork MPM (a single control process)

就启用模糊测试所需的代码更改而言，在这次练习中，我采用了一种新方法，而不是用本地文件描述符交换套接字来发送模糊输入。我创建了一个新的本地网络连接，并通过它发送模糊输入。

![](images/Pasted%20image%2020231102151548.png)

### Our traditional code changes
有关有效模糊网络服务器所需的一般代码更改，请查看[previous post series](https://securitylab.github.com/research/fuzzing-sockets-FreeRDP/)。不过，请继续阅读，以了解一些最重要更改的简要总结。

总的来说，这些变化可以分为以下几类：

- 旨在减少熵的变化：
	- 用常量种子替换 "random"和 "rand"：[Example](https://github.com/antonio-morales/Apache_2.5.1/commit/e0be82bce715dda77841de3360f6328d26aa35cb#diff-1d0396bf58a901188f8858c71c9ba6ea2cae5c8fc480565079fb2911c45c9bbcR5659)
	- 用常量种子替换 "time()"、"localtime() "和 "gettimeoftheday() "调用
	- 用固定值替换 "getpid()"调用：[Example](https://github.com/antonio-morales/Apache_2.5.1/commit/e0be82bce715dda77841de3360f6328d26aa35cb#diff-1d0396bf58a901188f8858c71c9ba6ea2cae5c8fc480565079fb2911c45c9bbcR5626)
- 旨在减少延迟的更改：
	- 删除部分 "sleep() "和 "select() "调用：

![](images/Pasted%20image%2020231102151838.png)

- 加密例程中的更改：
	- 禁用校验和：[Example](https://github.com/antonio-morales/Apache_2.5.1/commit/72a7bed52975f3258ab56a53f67b56632ddf30a2#diff-485c57a981998a7b2fb43f90f2084667358ab10beea82a0d15269564fb7eeaa3R1468)
	- 设置静态nonces: [Example](https://github.com/antonio-morales/Apache_2.5.1/commit/72a7bed52975f3258ab56a53f67b56632ddf30a2#diff-54ad55cab9d74b14dd358a112365481763d8e6f28296b56b920c198352cee37bR385)

您可以查看以下补丁，了解有关这些更改的所有详细信息：

- [Patch1](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Patches/Patch1.patch)
- [Patch2](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Patches/Patch2.patch)

## The “fake” bug: when your tools deceive you
起初看起来只是 Apache HTTP 中的一个简单错误，但结果却复杂得多。我将详细介绍我在 heisenbug rabbithole中的旅程，因为它是一个很好的例子，说明进行根因分析有时是多么令人沮丧。此外，我认为这些信息对其他安全研究人员也非常有用，因为他们可能也会遇到同样的情况，即不确定错误究竟是在目标软件中还是在你的工具中。

故事开始于我检测到一个只能在 AFL++ 运行时重现的错误。当我试图直接在 Apache 的 httpd 二进制文件上重现它时，服务器并没有崩溃。此时，我脑海中闪过的第一个念头是，我正在处理一个非确定性错误。换句话说，这是一个在 N 种情况中只有一种情况会发生的错误。于是，我做的第一件事就是创建一个脚本，启动应用程序 10000 次，并将其 stdout 输出重定向到一个文件。但错误仍然没有出现。我又将执行次数增加到 100,000 次，但错误还是没有出现。

![](images/Pasted%20image%2020231102152145.png)

奇怪的是，每次我在 AFL++ 下运行时，都会持续触发该错误。因此，我考虑了环境和 ASAN 的影响因素，这些因素可能是造成神秘错误的罪魁祸首。但是，在对这一假设进行了数小时的深入研究之后，我仍然没有找到可靠重现错误所需的条件。

我开始怀疑我的工具可能在欺骗我，于是我决定使用 GDB 更深入地调查这个候选错误。

![](images/Pasted%20image%2020231102152226.png)

该文件是 ASAN 库的一部分，每次有新项目推入程序堆栈时都会调用它。但是，由于某些原因，s 链接表被破坏了。结果，由于 "s->link "表达式试图取消引用一个无效的内存地址，发生了分段故障。

会不会是 ASAN 库出现了新的错误？这在我看来不太可能，但我花的时间越多，这个错误就越能得到合理的解释。好的一面是，我学到了很多关于 ASAN 内部的知识。

但是，我在寻找链接表损坏的根源时遇到了很大的困难。到底是 Apache 的错还是 AFL++ 的错？此时，我开始使用[rr debugger](https://rr-project.org/)。rr 是一种 Linux 调试工具，用于记录和重放程序的执行，也就是所谓的反向执行调试器。rr 使我能够 "逆向 "找到错误的根本原因。

![](images/Pasted%20image%2020231102152407.png)

最后，我可以解释一下我们神秘的内存损坏 bug 的起源。AFL++ 使用共享内存位图来捕获覆盖进度。它在分支点注入的代码基本上等同于：

```
cur_location = <COMPILE_TIME_RANDOM>;
shared_mem[cur_location ^ prev_location]++;
prev_location = cur_location >> 1;
```

该位图的默认大小为 64kb，但如图所示，我们在 guard 变量中设置了 65576 的值。因此，在这种情况下，AFL++ 的模糊器溢出了 \_\_afl_area_ptr 数组，并覆盖了程序内存。如果我们试图使用小于最小要求的 Map Size，AFL++ 通常会发出警报。但在这种特殊情况下，它并没有这样做。我不知道原因何在，剩下的就是历史了。

解决这个错误的最终方法很简单，就是设置环境变量 MAP_SIZE=256000。我希望这则趣闻能对其他人有所帮助，并提醒他们有时你的工具可能会欺骗你！

## Apache Fuzzing
对于那些喜欢直奔主题的人来说（我并不推荐这样做！），以下是您自己开始对 Apache HTTP 进行模糊测试所需的知识：

- 在源代码中打上补丁：
```
patch -p2 < /Patches/Patch1.patch
patch -p2 < /Patches/Patch2.patch
```

- 配置和构建 Apache HTTP：
```bash
CC=afl-clang-fast CXX=afl-clang-fast++ CFLAGS="-g -fsanitize=address,undefined -fno-sanitize-recover=all" CXXFLAGS="-g -fsanitize=address,undefined -fno-sanitize-recover=all" LDFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -lm" ./configure --prefix='/home/user/httpd-trunk/install' --with-included-apr --enable-static-support --enable-mods-static=few --disable-pie --enable-debugger-mode --with-mpm=prefork --enable-negotiation=static --enable-auth-form=static --enable-session=static --enable-request=static --enable-rewrite=static --enable-auth_digest=static --enable-deflate=static --enable-brotli=static --enable-crypto=static --with-crypto --with-openssl --enable-proxy_html=static --enable-xml2enc=static --enable-cache=static --enable-cache-disk=static --enable-data=static --enable-substitute=static --enable-ratelimit=static --enable-dav=static
make -j8
make install
```

- 运行模糊器：
```bash
AFL_MAP_SIZE=256000 SHOW_HOOKS=1 ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0,debug=true,check_initialization_order=true,detect_stack_use_after_return=true,strict_string_checks=true,detect_invalid_pointer_pairs=2 AFL_DISABLE_TRIM=1 ./afl-fuzz -t 2000 -m none -i '/home/antonio/Downloads/httpd-trunk/AFL/afl_in/' -o '/home/antonio/Downloads/httpd-trunk/AFL/afl_out_40' -- '/home/antonio/Downloads/httpd-trunk/install/bin/httpd' -X @@
```

- [Patch1](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Patches/Patch1.patch)
- [Patch2](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Patches/Patch2.patch)
- [Apache example conf](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/tree/main/Conf%20Example)
- [Some input case examples](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/tree/main/Input%20Case)
- [Dictionary example](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Dictionaries/http_request_fuzzer.dict.txt)
- [Custom mutator examples](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/tree/main/Custom%20mutators)
- [Custom grammar example](https://github.com/antonio-morales/Apache-HTTP-Fuzzing/blob/main/Custom%20Grammars/http.json)

## To be continued…
在本系列的第二部分，我将深入探讨其他有趣的模糊问题，如自定义拦截器和文件监视器。我还将解释我是如何对 mod_dav 或 mod_cache 等一些特殊 mod 进行模糊处理的。

下期再见！

## References

- https://httpd.apache.org/docs/current/
- https://animal0day.blogspot.com/2017/07/from-fuzzing-apache-httpd-server-to-cve.html
- https://www.fuzzingbook.org/html/MutationFuzzer.htm
- https://github.com/AFLplusplus/AFLplusplus
