## 案例
C程序test.c：
```c
#include <stdio.h>

void func(int n){
	printf("%d\n",n);
}

int main(){
	int a;
	scanf("%d",&a);
	if(a>10){
		func(a);
		return 0;
	}
	else
	{
		func(a);
		return 0;
	}
}
```

编译生成可执行文件

```
gcc test.c -o test
```

查看反汇编

```bash
objdump -d test
```

angr生成CFG

```python
import angr
from angrutils import *
p = angr.Project('./test', load_options = {'auto_load_libs': False})
cfg = p.analyses.CFG()
plot_cfg(cfg, "ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)
```

![](images/Pasted%20image%2020230814114115.png)

## angr-CFG
对二进制文件进行的基本分析是控制流图。控制流图（CFG）是以基本程序块为节点，以jumps/calls/rets/etc为边的图。

在 angr 中，可以生成两种类型的 CFG：静态 CFG（CFGFast）和动态 CFG（CFGEmulated）。CFGFast 使用静态分析生成 CFG。它的速度明显更快，但理论上受到某些控制流转换只能在执行时解决这一事实的限制。CFGEmulated 使用符号执行来捕捉 CFG。虽然理论上它更准确，但速度却大大降低。由于仿真的准确性问题（系统调用、缺失的硬件功能等），它通常也不够完整。如果您不确定使用哪种 CFG，或在使用 CFGEmulated 时遇到问题，可以先尝试 CFGFast。

可以通过以下方法构建 CFG：
```
>>> import angr
# load your project
>>> p = angr.Project('/bin/true', load_options={'auto_load_libs': False})

# Generate a static CFG
>>> cfg = p.analyses.CFGFast()

# generate a dynamic CFG
>>> cfg = p.analyses.CFGEmulated(keep_state=True)
```

CFG 的核心是 NetworkX 数据图。这意味着所有正常的 NetworkX API 都可用：

```
>>> print("This is the graph:", cfg.graph)
>>> print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
```

CFG 图的节点是类 CFGNode 的实例。由于上下文的敏感性，一个给定的基本块在图中可以有多个节点（用于多种上下文）。

```
# this grabs *any* node at a given location:
>>> entry_node = cfg.get_any_node(p.entry)

# on the other hand, this grabs all of the nodes
>>> print("There were %d contexts for the entry block" % len(cfg.get_all_nodes(p.entry)))

# we can also look up predecessors and successors
>>> print("Predecessors of the entry point:", entry_node.predecessors)
>>> print("Successors of the entry point:", entry_node.successors)
>>> print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])
```












