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