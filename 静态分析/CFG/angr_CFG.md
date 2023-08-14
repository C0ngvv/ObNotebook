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

