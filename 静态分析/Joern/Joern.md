Joern 是一个用于静态代码分析的命令行工具，它包括一个交互式外壳和以代码属性图为中心的自动化功能。

Joern中的代码分析是使用CPG查询语言完成的，这是一种专门设计用于代码属性图的领域特定语言。它包含代码属性图中发现的各种节点的实际表示，以及用于查询它们的属性和彼此之间关系的有用函数。

## 属性图

属性图是由以下构建基块组成：

-   **Nodes and their types.** Nodes represent program constructs. This includes low-level language constructs such as methods, variables, and control structures, but also higher level constructs such as HTTP endpoints or findings. Each node has a type. The type indicates the type of program construct represented by the node, e.g., a node with the type represents a method while a node with type represents the declaration of a local variable.`METHOD``LOCAL`
-   **Labeled directed edges.** Relations between program constructs are represented via edges between their corresponding nodes. For example, to express that a method contains a local variable, we can create an edge with the label from the method's node to the local's node. By using labeled edges, we can represent multiple types of relations in the same graph. Moreover, edges are directed to express, e.g., that the method contains the local but not the other way around. Multiple edges may exist between the same two nodes.`CONTAINS`
-   **Key-Value Pairs.** Nodes carry key-value pairs (attributes), where the valid keys depend on the node type. For example, a method has at least a name and a signature while a local declaration has at least the name and the type of the declared variable.

总之，代码属性图是有向的、边标记标签的、 带属性的多重图，我们坚持每个节点至少携带 一个指示其类型的属性。

## 查询
查询由以下组件组成：

1.  _根对象_，它是对要查询_的代码属性图_的引用
2.  零个或多个节点类型步骤，它们是到给定类型的所有节点的原子遍历
3.  零个或多个筛选步骤、映射步骤或重复步骤
4.  零个或多个属性指令，用于引用遍历中节点的属性
5.  零个或多个执行指令，执行遍历并以特定格式返回结果
6.  零个或多个扩充指令，使用新节点、属性或边扩展代码属性图

最后，组件 2-7 可以组合成复杂步骤，就像编程语言的基本表达式可以组合成复杂表达式一样。

| Traversals |               Description               | Example                               |
| ---------- |:---------------------------------------:| ------------------------------------- |
| `.callIn`  | Return the call-sites of a given method | cpg.method.name("exit").callIn.code.l |





[Flawfinder开源C/C++静态扫描分析工具安装与使用 - sanduo blog (hksanduo.github.io)](https://hksanduo.github.io/2019/11/15/2019-11-15-flawfinder-install-and-use/#%E6%A1%88%E4%BE%8B%E8%AE%B2%E8%A7%A3)

[Quickstart | Joern Documentation](https://docs.joern.io/quickstart)

