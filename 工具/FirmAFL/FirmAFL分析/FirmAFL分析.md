
## AFL模糊测试网络数据包过程
在源码`FirmAFL_config/user.sh`中包含了alf-fuzz的调用命令
```
AFL="./afl-fuzz -m none -t 800000+ -Q -i ./inputs -o ./outputs -x keywords"
echo $AFL

chroot . \
${AFL} \
/bin/busybox @@
```

`-t`设置超时，单位ms； `-x` 设置字典

即它使用文件
