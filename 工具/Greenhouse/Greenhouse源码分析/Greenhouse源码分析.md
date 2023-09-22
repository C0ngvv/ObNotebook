# Greenhouse源码分析

main()->run()->主要是两个方法：setup_target()和patch_loop()。

## setup_target()
setup_target()是准备运行和修补的环境，主要做以下工作：

1. 计算img文件hash
2. 获取brand和name
3. sanitize和sudo检查
4. 固件解包和寻找文件系统
5. 寻找要运行的二进制程序
6. 设置qemu模拟环境，修补文件系统（处理特殊设备文件，获取架构和lib加载库，复制qemu和其它二进制，nvram配置等）

## patch_loop()
patch_loop()包含了修补的主要过程。

首先获取ip和port信息，获取bg脚本。刚开始启动一次FirmAE全系统仿真。

### apply_fullsystem_rehost()




