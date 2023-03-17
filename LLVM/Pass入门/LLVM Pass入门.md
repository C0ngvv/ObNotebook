### LLVM简介
编译过程主要可以划分为前端与后端：
- 前端把源代码翻译成中间表示 (IR)。
- 后端把IR编译成目标平台的机器码。当然，IR也可以给解释器解释执行。

LLVM的核心设计了一个叫 LLVM IR 的中间表示， 并以库(Library) 的方式提供一系列接口， 为你提供诸如操作IR、生成目标平台代码等等后端的功能。

LLVM Pass 又是什么呢？ Pass就是“遍历一遍IR，可以同时对它做一些操作”的意思。翻译成中文应该叫“趟”。 在实现上，LLVM的核心库中会给你一些 Pass类 去继承。你需要实现它的一些方法。 最后使用LLVM的编译器会把它翻译得到的IR传入Pass里，给你遍历和修改。

那LLVM Pass有什么用呢？
- 显然它的一个用处就是插桩： 在Pass遍历LLVM IR的同时，自然就可以往里面插入新的代码。
- 机器无关的代码优化：大家如果还记得编译原理的知识的话，应该知道IR在被翻译成机器码前会做一些机器无关的优化。 但是不同的优化方法之间需要解耦，所以自然要各自遍历一遍IR，实现成了一个个LLVM Pass。 最终，基于LLVM的编译器会在前端生成LLVM IR后调用一些LLVM Pass做机器无关优化， 然后再调用LLVM后端生成目标平台代码。
- 静态分析： 像VSCode的C/C++插件就会用LLVM Pass来分析代码，提示可能的错误 (无用的变量、无法到达的代码等等)。

再次强调，**LLVM的核心是一个库**，而不是一个具体的二进制程序。 不过，LLVM这个项目本身也基于这个库实现了周边的工具， 下面列出了几个重要的命令行工具，光看名字就可以知道它们大概在做什么：

-   `llvm-as`：把LLVM IR从人类能看懂的文本格式汇编成二进制格式。注意：此处得到的不是目标平台的机器码。
-   `llvm-dis`：`llvm-as`的逆过程，即反汇编。 不过这里的反汇编的对象是LLVM IR的二进制格式，而不是机器码。
-   `opt`：优化LLVM IR，输出新的LLVM IR。
-   `llc`：把LLVM IR编译成汇编码，需要用`as`进一步得到机器码。
-   `lli`：解释执行LLVM IR。

打开github上的LLVM的源代码来更直观地了解一下这个项目。（这里LLVM的源代码隶属于llvm project仓库）
[llvm-project/llvm at main · llvm/llvm-project (github.com)](https://github.com/llvm/llvm-project/tree/main/llvm)

1.  根目录下，最重要的就是include和lib这两个文件夹。include文件夹包含了其它项目在使用LLVM核心库时需要包含的头文件，而lib文件夹里放的就是LLVM核心库的实现。分别打开lib和include，可以看到很多文件与子文件夹。 有经验的读者应该能从名字大概猜到其实现的东西。比如，lib/IR子文件夹肯定是存放了与IR相关的代码，lib/ Target子文件夹肯定与生成目标平台机器码有关。又比如，include/llvm/Pass.h文件里面声明了Pass类用来给你继承去遍历、修改LLVM IR。
2.  根目录下还有一个tools文件夹，这里面就存放了我上面所说的周边工具。 打开这个目录，就可以看到类似llvm-as这样的子目录。显然这就是`llvm-as`的实现。

 如果读者还想了解更多，可以去看看官方文档所推荐的[介绍文章](https://link.zhihu.com/?target=https%3A//llvm.org/docs/%23llvm-design-overview)。 其中我看过的是[Intro to LLVM](https://link.zhihu.com/?target=http%3A//www.aosabook.org/en/llvm.html)，讲得挺不错的。

Clang是一个基于LLVM的编译器驱动。它提供了把C/C++/OC等语言翻译成LLVM IR的前端，并使用LLVM的库实现了LLVM IR到目标平台的后端。既然我们的目标是写一个 LLVM Pass，那么我们自然就需要安装 LLVM 提供的库了。 另外，我们也需要用 Clang 编译得到 LLVM IR，所以 Clang 也是必须要安装的。

在Ubuntu上，可以直接通过apt安装llvm和clang：
```bash
$ sudo apt install llvm
$ sudo apt install clang
```

如果需要安装更高的版本，有两种方法：
1.  使用`sudo apt install llvm-x.y clang-x.y`来指定安装当前源可获取的版本。一般可以通过在输入完`sudo apt install llvm-`时按下`tab`键查看有哪些版本可以获取。这个方法的局限是：可安装的最高版本一般不会是最新版本。
2.  想要安装最新版本，可以根据 [apt.llvm.org](https://link.zhihu.com/?target=https%3A//apt.llvm.org/)这个网站列出的方法配置源并安装。

后续我们会用到`clang`、`opt`、`llvm-config`等指令。请记得把它们加进`PATH` 环境变量中。

关于LLVM IR，首先阅读[PowerPoint Presentation (llvm.org)](https://llvm.org/devmtg/2019-04/slides/Tutorial-Bridgers-LLVM_IR_tutorial.pdf)（它是来自于一个会议的presentation，英语好的可以[去Youtube看对应的视频](https://link.zhihu.com/?target=https%3A//youtu.be/m8G_S5LwlTo)）。看完后，读者现在应该对LLVM IR有了基本了解了。

LLVM IR实际上有三种表示：
1.  .ll 格式：人类可以阅读的文本。
2.  .bc 格式：适合机器存储的二进制文件。
3.  内存表示

.ll格式和.bc格式是如何生成并相互转换的呢？下面我列了个常用的简单指令清单：
-   .c -> .ll：`clang -emit-llvm -S a.c -o a.ll`
-   .c -> .bc: `clang -emit-llvm -c a.c -o a.bc`
-   .ll -> .bc: `llvm-as a.ll -o a.bc`
-   .bc -> .ll: `llvm-dis a.bc -o a.ll`
-   .bc -> .s: `llc a.bc -o a.s`

`clang`通过`-emit-llvm`参数， 使得原本要生成汇编以及机器码的指令生成了LLVM IR的ll格式和bc格式。 这可以理解为：对于LLVM IR来说，.ll文件就相当于汇编，.bc文件就相当于机器码。 这也是`llvm-as`和`llvm-dis`指令为什么叫`as`和`dis`的缘故。

如果想要更详细地了解llvm的相关工具，请查阅官方文档 [LLVM CommandGuide](https://link.zhihu.com/?target=https%3A//llvm.org/docs/CommandGuide/index.html)。 对于clang，请查阅官方文档 [User Manual](https://link.zhihu.com/?target=https%3A//clang.llvm.org/docs/UsersManual.html)。

其次，LLVM IR的内存表示在写LLVM Pass的时候会用到。读者可以现在阅读官方文档 [ProgrammersManual - The Core LLVM Class Hierarchy Reference](https://link.zhihu.com/?target=https%3A//llvm.org/docs/ProgrammersManual.html%23the-core-llvm-class-hierarchy-reference) 这一小节来学习。

### 编写LLVM PASS
请读者仔细阅读官方文档

[Writing an LLVM Pass​llvm.org/docs/WritingAnLLVMPass.html](https://link.zhihu.com/?target=https%3A//llvm.org/docs/WritingAnLLVMPass.html)

中 [Introduction](https://link.zhihu.com/?target=https%3A//llvm.org/docs/WritingAnLLVMPass.html%23introduction-what-is-a-pass) 和[Quick Start](https://link.zhihu.com/?target=https%3A//llvm.org/docs/WritingAnLLVMPass.html%23quick-start-writing-hello-world) 这两部分，然后略读 [Pass classes and requirements](https://link.zhihu.com/?target=https%3A//llvm.org/docs/WritingAnLLVMPass.html%23pass-classes-and-requirements) 与[Pass Statistics](https://link.zhihu.com/?target=https%3A//llvm.org/docs/WritingAnLLVMPass.html%23pass-statistics) 这两部分。

在官方文档中，Hello Pass是基于源代码项目构建的。 如果你没有源代码，那么构建Pass的部分可以简单略读。


参考：

[LLVM Pass入门导引 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/122522485)

