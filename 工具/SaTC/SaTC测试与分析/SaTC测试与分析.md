首先测试一个固件，然后基于分析结果查看SaTC源码各部分功能。

## Netgear R6400v2测试
固件来自于其提供的测试案例，这里测试其中的Netgear R6400v2的命令注入和缓冲区溢出。
```
python satc.py -d /workspace/NetGear/RV6400_v2/squashfs-root -o /workspace/NetGear/RV6400_v2/output --ghidra_script=ref2sink_cmdi --ghidra_script=ref2sink_bof --taint_check
```

![](images/Pasted%20image%2020231016224033.png)

