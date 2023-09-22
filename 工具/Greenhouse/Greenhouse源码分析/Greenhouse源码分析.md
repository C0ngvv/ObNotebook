# Greenhouse源码分析

main()->run()->主要是两个方法：setup_target()和patch_loop()。

setup_target()主要做以下工作：

1. 计算img文件hash
2. 获取brand和name
3. sanitize和sudo检查
4. 固件解包和寻找文件系统
5. 寻找要运行的二进制程序
6. 




