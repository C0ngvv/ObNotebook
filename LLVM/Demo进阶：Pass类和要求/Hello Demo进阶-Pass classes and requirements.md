## ImmutablePass Class
这种类型pass不需要运行、不改变状态、不需要更新，它不是一个正常的transformation或analysis类型，但是提供关于当前编译器配置的信息。

这个类型使用频率低，但可以提供当前正在编译的目标机的信息以及其他可以影响各种转换的静态信息。

`ImmutablePasses` 永远不会使其他transformation失效，永远不会被废止，也不会被 "运行"。

## ModulePass Class
所有超类里最通用的一种，从该类继承意味着pass使用整个程序作为一个单元，以不可预测的顺序引用函数体，或添加和删除函数。因为对ModulePass子类的行为一无所知，所以不能对其执行进行优化。

一个module pass可以使用function级的pass（比如dominators），使用`getAnalysis` 接口`getAnalysis<DominatorTree>(llvm::Function *)` 来提供检索分析结果的函数，如果该function pass不需要任何模块或不可变的传递。注意，这只能针对分析运行的函数，例如，在dominator的情况下，你应该只要求`DominatorTree`的函数定义，而不是声明。

要编写一个正确的`ModulePass`子类，应从`ModulePass`派生，并以下列签名重载`runOnModule`方法：

```cpp
virtual bool runOnModule(Module &M) = 0;
```

`runOnModule`方法执行了有趣的传递工作。如果模块被转换所修改，它应该返回true，否则返回false。

## CallGraphSCCPass Class




## FunctionPass Class

## LoopPass Class

## RegionPass Class

## MachineFunctionPass Class

## Pass registration

## Specify interactions between passes

## Implementing Analysis Groups



