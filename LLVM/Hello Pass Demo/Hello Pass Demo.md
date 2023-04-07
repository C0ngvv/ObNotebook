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

编译为bc格式
```bash
clang -c -emit-llvm hello.c -o hello.bc 
```

## 4. 运行pass
结果打印出了定义的函数
```
opt -load ./LLVMHello.so -hello -enable-new-pm=0 hello.bc -o /dev/null
```

![](images/Pasted%20image%2020230407101304.png)