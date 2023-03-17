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




参考：

[LLVM Pass入门导引 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/122522485)

