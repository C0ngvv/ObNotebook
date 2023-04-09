## ImmutablePass Class
这种类型pass不需要运行、不改变状态、不需要更新，它不是一个正常的transformation或analysis类型，但是提供关于当前编译器配置的信息。

这个类型使用频率低，但可以提供当前正在编译的目标机的信息以及其他可以影响各种转换的静态信息。

`ImmutablePasses` 永远不会使其他transformation失效，永远不会被废止，也不会被 "运行"。

## ModulePass Class
所有超类里最通用的一种，从该类继承意味着pass使用整个程序作为一个单元，以不可预测的顺序引用函数体，或添加和删除函数。因为对ModulePass子类的行为一无所知，所以不能对其执行进行优化。

一个module pass可以使用function级的pass（比如dominators），使用`getAnalysis` 接口`getAnalysis<DominatorTree>(llvm::Function *)` 来提供检索分析结果的函数，如果该function pass不需要任何模块或不可变的传递。注意，这只能针对分析运行的函数，例如，在dominator的情况下，你应该只要求`DominatorTree`的函数定义，而不是声明。

要编写一个正确的`ModulePass`子类，应从`ModulePass`派生，并以下列签名重载`runOnModule`方法：

### runOnModule method
```cpp
virtual bool runOnModule(Module &M) = 0;
```

`runOnModule`方法执行了有趣的传递工作。如果模块被转换所修改，它应该返回true，否则返回false。

## CallGraphSCCPass Class
CallGraphSCCPass被那些需要在调用图上自下而上地遍历程序的pass所使用（被调用者在调用者前）。从CallGraphSCCPass派生出来，提供了一些构建和遍历CallGraph的机制，也允许系统优化CallGraphSCCPasses的执行。如果你的传递满足下面的要求，并且不符合FunctionPass的要求，你应该派生自CallGraphSCCPass。

明确地说，CallGraphSCCPass的子类是：
- 不允许检查或修改除当前SCC中的功能以及SCC的直接调用者和直接被调用者之外的任何功能
- 需要保留当前的CallGraph对象，更新它以反映对程序所做的任何改变
- 不允许从当前模块中添加或删除SCC，尽管他们可以改变SCC的内容
- 允许从当前模块中添加或删除全局变量
- 允许在runOnSCC的调用中保持状态（包括全局数据）

实现CallGraphSCCPass在某些情况下略显棘手，因为它必须处理其中有不止一个节点的SCC。下面描述的所有虚拟方法，如果它们修改了程序，应该返回true，如果没有，则返回false。

### doInitialization(CallGraph &CG) method
```cpp
virtual bool doInitialization(CallGraph &CG);
```

`doInitialization` 方法允许做大部分`CallGraphSCCPasses` 不允许做的事情。他们可以添加和删除函数，获得函数的指针，等等。`doInitialization` 方法被设计用来做简单的初始化类型的事情，不依赖于正在处理的SCC。`doInitialization` 方法的调用并不安排与任何其他传递的执行重叠（因此它应该是非常快的）。

### runOnSCC method
```cpp
virtual bool runOnSCC(CallGraphSCC &SCC) = 0;
```

runOnSCC方法执行有趣的传递工作，如果模块被转换所修改，应该返回true，否则返回false。

### doFinalization(CallGraph &CG) method
```
virtual bool doFinalization(CallGraph &CG);
```

`doFinalization` 方法是一个不经常使用的方法，当传递框架为正在编译的程序中的每一个SCC调用完runOnSCC时，它就会被调用。

## FunctionPass Class
与`ModulePass` 子类相比，`FunctionPass` 子类确实有一个可预测的局部行为，可以被系统所期待。所有`FunctionPass` 在程序中的每个函数上执行，独立于程序中的所有其他函数。`FunctionPasses` 不要求以特定的顺序执行，`FunctionPasses` 也不修改外部函数。

明确地说，FunctionPass的子类不允许：
- 检查或修改当前正在处理的函数以外的函数
- 从当前模块中添加或删除函数。
- 从当前模块中添加或删除全局变量
- 在runOnFunction的调用中保持状态（包括全局数据）

实现一个FunctionPass通常很简单（参见Hello World pass的例子）。FunctionPasses可以重载三个虚拟方法来完成其工作。所有这些方法如果修改了程序就应该返回true，如果没有就应该返回false。

### doInitialization(Module &M) method
```cpp
virtual bool doInitialization(Module &M);
```

doInitialization方法被允许做大多数FunctionPasses不允许做的事情。他们可以添加和删除函数，获得函数的指针，等等。doInitialization方法被设计用来做简单的初始化类型的事情，不依赖于被处理的函数。doInitialization方法的调用不会与任何其他传递的执行重叠（因此它应该是非常快的）。

一个很好的例子是LowerAllocations传递，说明这个方法应该如何使用。这个传递将malloc和free指令转换为与平台相关的malloc()和free()函数调用。它使用doInitialization方法来获取它所需要的malloc和free函数的引用，如果有必要的话，将原型添加到模块中。

### runOnFunction(Function &F) method
```cpp
virtual bool runOnFunction(Function &F) = 0;
```

runOnFunction方法必须由子类实现，以完成你的传递的转换或分析工作。像往常一样，如果函数被修改，应该返回一个真值。

### doFinalization(Module &M) method
```cpp
virtual bool doFinalization(Module &M);
```

doFinalization方法是一个不经常使用的方法，当传递框架为正在编译的程序中的每一个函数调用完runOnFunction后，该方法就会被调用。

## LoopPass Class
所有的`LoopPass` 在函数中的每个循环上执行，与函数中的所有其他循环无关。`LoopPass` 按照循环嵌套的顺序处理循环，最外层的循环最后被处理。

`LoopPass` 的子类允许使用`LPPassManager` 接口来更新循环嵌套。实现一个循环pass通常是简单的。LoopPasses 可以重载三个虚方法来完成其工作。所有这些方法如果修改了程序就应该返回true，如果没有就应该返回false。

一个打算作为主循环传递管道的一部分运行的LoopPass子类，需要保留其管道中其他循环传递所需要的所有相同的函数分析。为了使之更容易，LoopUtils.h提供了一个`getLoopAnalysisUsage` 函数，可以在子类的`getAnalysisUsage` 重载中调用，以获得一致和正确的行为。类似地，`INITIALIZE_PASS_DEPENDENCY(LoopPass)` 将初始化这组函数的分析。

### doInitialization(Loop \*, LPPassManager &LPM) method
```cpp
virtual bool doInitialization(Loop *, LPPassManager &LPM);
```

doInitialization方法被设计用来做简单的初始化类型的事情，不依赖于正在处理的函数。doInitialization方法的调用不会与任何其他通行证的执行相重叠（因此它应该是非常快的）。LPPassManager接口应该被用来访问函数或模块级别的分析信息。

### runOnLoop(Loop \*, LPPassManager &LPM) method
```cpp
virtual bool runOnLoop(Loop *, LPPassManager &LPM) = 0;
```

runOnLoop方法必须由子类实现，以完成传递的转换或分析工作。像往常一样，如果该函数被修改，应该返回一个真值。应使用LPPassManager接口来更新循环nest。

### doFinalization() method
```cpp
virtual bool doFinalization();
```

doFinalization方法是一个不经常使用的方法，当传递框架为正在编译的程序中的每一个循环调用完runOnLoop后，该方法就会被调用。

## RegionPass Class
RegionPass与LoopPass相似，但在函数中的每个单入单出区域上执行。RegionPass以嵌套的方式处理区域，即最外层的区域被最后处理。

RegionPass的子类被允许通过使用RGPassManager接口来更新区域树。你可以重载 RegionPass 的三个虚拟方法来实现你自己的区域传递。所有这些方法如果修改了程序，应该返回true，如果没有，则返回false。

### doInitialization(Region \*, RGPassManager &RGM) method
```cpp
virtual bool doInitialization(Region *, RGPassManager &RGM);
```

doInitialization方法被设计用来做简单的初始化类型的事情，不依赖于正在处理的函数。doInitialization方法的调用不会与任何其他通行证的执行相重叠（因此它应该是非常快的）。RPPassManager接口应该被用来访问函数或模块级别的分析信息。

### runOnRegion(Region \*, RGPassManager &RGM) method
```cpp
virtual bool runOnRegion(Region *, RGPassManager &RGM) = 0;
```

runOnRegion方法必须由子类实现，以完成你的传递的转换或分析工作。像往常一样，如果区域被修改，应该返回一个真值。RGPassManager接口应该被用来更新区域树。

### doFinalization() method
```cpp
virtual bool doFinalization();
```

doFinalization方法是一个不经常使用的方法，当传递框架为正在编译的程序中的每一个区域调用完runOnRegion后，该方法被调用。

## MachineFunctionPass Class
MachineFunctionPass是LLVM代码生成器的一部分，它在程序中的每个LLVM函数的机器独立的表示上执行。

代码生成器pass由`TargetMachine::addPassesToEmitFile` 和类似的例程专门注册和初始化，因此它们一般不能从opt或bugpoint命令中运行。

一个MachineFunctionPass也是一个FunctionPass，所以适用于FunctionPass的所有限制也适用于它。MachineFunctionPasses也有额外的限制。特别是，MachineFunctionPasses不允许做以下任何事情：

- 修改或创建任何LLVM IR指令、基本块、参数、函数、GlobalVariables、GlobalAliases或模块。
- 修改当前正在处理的机器功能以外的机器功能
- 在runOnMachineFunction的调用中保持状态（包括全局数据）

### runOnMachineFunction(MachineFunction &MF) method
```cpp
virtual bool runOnMachineFunction(MachineFunction &MF) = 0;
```

runOnMachineFunction可以被认为是MachineFunctionPass的主要入口点；也就是说，你应该覆盖这个方法来完成你的MachineFunctionPass的工作。

runOnMachineFunction方法在模块中的每个MachineFunction上被调用，以便MachineFunctionPass可以对函数的机器独立性表示进行优化。如果你想获得你正在处理的MachineFunction的LLVM Function，请使用MachineFunction的getFunction()访问器方法--但记住，你不能从MachineFunctionPass中修改LLVM Function或其内容。

## Pass registration
在Hello World例子中，我们说明了pass注册是如何工作的，并讨论了使用pass注册的一些原因和它的作用。这里我们讨论如何以及为什么要注册pass。

正如我们在上面看到的，pass是用`RegisterPass`模板注册的。模板参数是通证的名称，在命令行中用来指定该pass应该被添加到程序中（例如，用opt或bugpoint）。第一个参数是pass的名称，用于程序的-help输出，以及由-debug-pass选项产生的调试输出。

如果你想让你的pass容易转储，你应该实现虚拟打印方法：

### print(llvm::raw_ostream &O, const Module \*M) method
```cpp
virtual void print(llvm::raw_ostream &O, const Module *M) const;
```

打印方法必须由 "分析 "来实现，以便打印出分析结果的人类可读版本。这对调试分析本身很有用，也可以让其他人弄清楚分析的工作原理。使用opt -analyze参数来调用这个方法。

llvm::raw_ostream参数指定了写入结果的流，Module参数给出了一个指向被分析的程序的顶级模块的指针。但是请注意，这个指针在某些情况下可能是空的（比如从调试器中调用Pass::dump()），所以它只应该被用来加强调试输出，不应该被依赖。

## Specify interactions between passes
PassManager的主要职责之一是确pass之间正确互动。因为PassManager试图优化pass的执行，它必须知道pass之间如何相互作用，以及各个pass之间存在哪些依赖关系。为了跟踪这一点，每个pass可以声明在当前pass之前需要执行的pass集合，以及被当前pass废止的pass。

通常情况下，这个功能被用来要求在你的pass运行之前计算出分析结果。运行任意的转换pass会使计算的分析结果无效，这就是无效集所指定的。如果一个pass没有实现getAnalysisUsage方法，它默认为没有任何先决条件的传递，并使所有其他传递无效。

### getAnalysisUsage(AnalysisUsage &Info) method
```cpp
virtual void getAnalysisUsage(AnalysisUsage &Info) const;
```

通过实现getAnalysisUsage方法，可以为你的转换指定需要的和无效的集合。实现应该在AnalysisUsage对象中填入关于哪些pass是必需的、哪些pass没有失效的信息。为了做到这一点，pass可以调用AnalysisUsage对象上的以下任何方法：

### AnalysisUsage::addRequired<> and AnalysisUsage::addRequiredTransitive<> methods
如果你的pass需要执行先前的pass（例如分析），它可以使用这些方法之一来安排它在你的pass之前运行。LLVM有许多不同类型的分析和pass可以被要求，范围包括从`DominatorSet` 到`BreakCriticalEdges` 。例如，要求`BreakCriticalEdges` ，可以保证当你的传递被运行时，CFG中没有临界边缘。

一些分析与其他分析连锁，以完成它们的工作。例如，一个别名分析AliasAnalysis \<AliasAnalysis\>的实现需要与其他别名分析pass链接。在分析链的情况下，应该使用`addRequiredTransitive`方法而不是`addRequired`方法。这通知PassManager，只要需要的pass是活的，那么过渡性需要的pass就应该是活的。

### AnalysisUsage::addPreserved<> method
PassManager的工作之一是优化分析的运行方式和时间。特别是，它试图避免重新计算数据，除非它需要这样做。出于这个原因，允许通行证声明他们保留（即，他们不会使现有的分析无效），如果它是可用的。例如，一个简单的常数折叠传递不会修改CFG，所以它不可能影响dominator分析的结果。默认情况下，所有的传递都被假定为使所有其他的传递无效。

AnalysisUsage类提供了几个方法，这些方法在某些情况下很有用，与addPreserved有关。特别是，可以调用setPreservesAll方法来表示该通证完全不修改LLVM程序（这对分析来说是真实的），而setPreservesCFG方法可以被改变程序中的指令但不修改CFG或终止器指令的转换所使用。

addPreserved对于像BreakCriticalEdges这样的转换特别有用。这个传递知道如何更新一小部分循环和支配者相关的分析，如果它们存在的话，所以它可以保留它们，尽管它对CFG进行了黑客攻击。



## Implementing Analysis Groups



