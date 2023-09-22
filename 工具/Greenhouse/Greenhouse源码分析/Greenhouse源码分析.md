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
设置运行缓存路径，然后run_firmae()运行firmae。

#### run_firmae()
1. 构建firmae执行脚本firmae_cmd，执行
2. 获取IID，获取fileList和bgcmds
3. 测试连接和telnet
4. 连接telnet，执行获取相应信息

创建缓存路径，调用firmae.mount_and_cache_fs()：挂在文件系统raw，并将内容复制到缓存目录，然后删除受保护的目标。

调用gh.clean_fs()，处理可能被创建的特殊文件（块或字符等设备文件，移除.conf文件Interface信息）。

nvram值。复制qemu.final.serial.log到缓存路径，根据需要清除FirmAE仿真环境。

更新ps和cwd，根据qemu.final.serial.log文件和原始nvram配置更新

\##### PATCH LOOP ######







