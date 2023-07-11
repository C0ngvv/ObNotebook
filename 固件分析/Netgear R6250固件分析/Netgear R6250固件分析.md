从官网下载R6250固件，版本为1.0.4.48。

使用binwalk解包，然后利用strings查看init程序为`sbin/preinit`。

![](images/Pasted%20image%2020230712001824.png)

对`sbin/preinit`是`rc`程序的软连接，将`rc`拖进IDA进行分析

![](images/Pasted%20image%2020230712002042.png)