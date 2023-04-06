原文：[Writing an LLVM Pass — LLVM 17.0.0git documentation](https://www.llvm.org/docs/WritingAnLLVMPass.html)

## 引言-什么是Pass
LLVM Pass框架是LLVM系统的一个重要部分，因为LLVM Pass是编译器中大多数有趣部分的存在。Pass执行构成编译器的转换（transformations）和优化（optimizations），它们建立了这些转换所使用的分析结果，而且它们首先是编译器代码的结构化技术。

所有LLVM的pass都是[Pass](https://llvm.org/doxygen/classllvm_1_1Pass.html)类的子类，它们通过覆写从`Pass` 继承的虚拟方法来实现功能。根据你的pass的工作方式，你应该继承[ModulePass](https://www.llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-modulepass)、[CallGraphSCCPass](https://www.llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-callgraphsccpass)、[FunctionPass](https://www.llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-functionpass)、或[LoopPass](https://www.llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-looppass)、或[RegionPass](https://www.llvm.org/docs/WritingAnLLVMPass.html#writing-an-llvm-pass-regionpass)类，这给了系统更多关于你的Pass做什么的信息，以及它如何与其他Pass结合。LLVM Pass框架的主要特点之一是，它根据你的pass所满足的约束条件（这些约束条件由它们派生的类来表示），可以以有效的方式安排pass运行。

我们首先向你展示如何构建一个Pass，从设置代码，到编译、加载和执行它的一切。在基础知识结束后，我们将讨论更多的高级功能。

## Quick Start-Writing hello world
这里我们描述如何编写 "hello world "的pass。"Hello " pass的目的是简单地打印出存在于被编译程序中的非外部函数的名称。它完全不修改程序，只是对其进行检查。这个通道的源代码和文件可以在LLVM源码树的lib/Transforms/Hello目录下找到。

### Setting up the build environment





