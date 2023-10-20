启动模拟，Qiling()参数中加入`verbose=QL_VERBOSE.DEBUG`可以显示更详细的信息。
```python
from qiling import *
path = r"examples/rootfs/arm_linux/bin/arm_hello".split()
rootfs = r"examples/rootfs/arm_linux/"
ql = Qiling(path, rootfs)
ql.run()
```

初始化

## 基本使用方法
### 初始化
```
ql = Qiling()
```



### 配置


### 运行
```
ql.run(begin, end, timeout, count)
```