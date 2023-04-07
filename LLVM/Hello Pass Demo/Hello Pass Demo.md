本文介绍无脑跑一个Hello Pass小Demo过程。
## 0. 介绍
Hello Pass是用来输出程序中定义的函数名，官方文档位于[Writing an LLVM Pass — LLVM 13 documentation](https://releases.llvm.org/13.0.1/docs/WritingAnLLVMPass.html)

![](images/Pasted%20image%2020230407101442.png)

## 1. 安装llvm环境
使用的是预编译的llvm13.0.1版本，可访问[LLVM Download Page](https://releases.llvm.org/download.html) 查看下载版本。下面是环境安装过程：
1. 下载预编译版本
2. 放在/usr/local目录下解压、重命名
3. 将llvm bin目录添加到环境变量
```bash
cd /usr/local
sudo wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
sudo tar xvf clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
sudo mv clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz llvm-13.0.1
export PATH="$PATH:/usr/local/llvm-13.0.1/bin"
```

然后就可以使用了，使用下面命令测试
```
clang -v
```

![](images/Pasted%20image%2020230407100625.png)

## 2. 编写Pass
编写LLVMHello.cpp文件
```cpp
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {
struct Hello : public FunctionPass {
  static char ID;
  Hello() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    errs() << "Hello: ";
    errs().write_escaped(F.getName()) << '\n';
    return false;
  }
}; // end of struct Hello
}  // end of anonymous namespace

char Hello::ID = 0;
static RegisterPass<Hello> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);

static RegisterStandardPasses Y(
    PassManagerBuilder::EP_EarlyAsPossible,
    [](const PassManagerBuilder &Builder,
       legacy::PassManagerBase &PM) { PM.add(new Hello()); });
```

使用该命令生成`LLVMHello.so`文件
```bash
clang `llvm-config --cxxflags` -Wl,-znodelete -fno-rtti -fPIC -shared LLVMHello.cpp -o LLVMHello.so `llvm-config --ldflags`
```

## 3. 编写源程序
创建`hello.c` 程序
```c
#include <stdio.h>

void func1(){
  printf("what is this?\n");
}

int main() {
  printf("hello world!\n");
  return 0;
}
```

编译为bc格式（bc格式是IR的位码bitcode表示）
```bash
clang -c -emit-llvm hello.c -o hello.bc 
```
- `clang [options] file ...`
- `-c` 仅运行预处理、编译和组装步骤
- `-emit-llvm` 对汇编程序和目标文件使用LLVM表示
- `-o <file>` 指定输出文件

## 4. 运行pass
结果打印出了定义的函数
```
opt -load ./LLVMHello.so -hello -enable-new-pm=0 hello.bc -o /dev/null
```

![](images/Pasted%20image%2020230407101304.png)

## 5. 工作原理
## Pass编写
由于我们在写一个Pass，并操作在Function上，还有一些打印操作，所以需要包含下面的包。
```cpp
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
```

从include文件导入的functions都在llvm的命名空间内，所以使用llvm命名空间。
```cpp
using namespace llvm;
```

下面这条语句开始一个匿名命名空间。匿名命名空间对于C++来说就像 "静态 "关键字对于C语言一样（在全局范围内）。在匿名命名空间中声明的东西只对当前文件可见。
```cpp
namespace {
```

现在来声明我们的pass。这里声明了一个FunctionPass的子类"Hello"类，FuncionPass一次只对一个函数进行操作。
```cpp
struct Hello : public FunctionPass {
```

这声明了LLVM用来识别pass的标识符。这使得LLVM可以避免使用昂贵的C++运行时信息。
```cpp
static char ID;
Hello() : FunctionPass(ID) {}
```

这里声明了一个`runOnFunction` 方法，它重写了一个继承自`FunctionPass` 的抽象虚方法。这里面写我们要做的事，这里是打印出"hello: "和每个函数的名称。
```cpp
  bool runOnFunction(Function &F) override {
    errs() << "Hello: ";
    errs().write_escaped(F.getName()) << '\n';
    return false;
  }
}; // end of struct Hello
}  // end of anonymous namespace
```

这里初始化pass ID。LLVM使用ID的地址来识别一个pass，所以初始化的值是不重要的。
```cpp
char Hello::ID = 0;
```

最后，注册我们编写的`Hello` 类，给它一个命令行参数`hello`和名字`Hello World Pass` ，最后两个参数描述它的行为：如果一个pass遍历CFG而不修改的情况下，那么第三个参数被设置为`true` ；如果一个通道是一个分析通道，例如dominator tree pass，那么第四个参数被设置为`true`。
```cpp
static RegisterPass<Hello> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
```

如果我们想把pass注册为现有管道的一个步骤，一些扩展点可以使用，例如`PassManagerBuilder::EP_EarlyAsPossible` 来在任何优化前应用我们的pass，或使用`PassManagerBuilder::EP_FullLinkTimeOptimizationLast` 来在链接时优化后应有pass。
```
static llvm::RegisterStandardPasses Y(
    llvm::PassManagerBuilder::EP_EarlyAsPossible,
    [](const llvm::PassManagerBuilder &Builder,
       llvm::legacy::PassManagerBase &PM) { PM.add(new Hello()); });
```

### opt
可以使用`opt` 命令使用pass运行llvm程序。
```
opt -load ./LLVMHello.so -hello -enable-new-pm=0 hello.bc -o /dev/null
```

- `-load` 参数指定加载自己的pass作为共享对象
- `-hello` 是注册的类
- 这里没有修改程序，所以将opt的输出丢给`/dev/null`即可
- `-enable-new-pm=0` 这篇文章使用的是legacy pass manager，LLVM使用新的默认pass管理器，所以使用该参数来启用legacy pass manager

opt其他参数
`-help` 显示帮助
```
opt -load ./LLVMHello.so -help
```

`-time-passes`显示pass的执行时间
```
opt -load ./LLVMHello.so -hello -enable-new-pm=0 -time-passes hello.bc -o /dev/null
```

![](images/Pasted%20image%2020230407150725.png)

