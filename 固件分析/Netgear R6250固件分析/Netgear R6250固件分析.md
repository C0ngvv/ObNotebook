从官网下载R6250固件，版本为1.0.4.48。

使用binwalk解包，然后利用strings查看init程序为`sbin/preinit`。

![](images/Pasted%20image%2020230712001824.png)

对`sbin/preinit`是`rc`程序的软连接，将`rc`拖进IDA进行分析

![](images/Pasted%20image%2020230712002042.png)

系统以`preinit`启动后，进入这一块代码执行。

![](images/Pasted%20image%2020230712005055.png)

简单分析没有找到启动`httpd`的命令，然后在linux中搜索包含`httpd`字符串程序的程序，发现一个名为`sbin/acos_service`的程序。

![](images/Pasted%20image%2020230712005233.png)

在`rc`程序里尝试搜索`acos_service`字符串，发现它就位于上面代码中的`sub_E5E4`函数中，可以看到执行了`acos_service start`命令。

![](images/Pasted%20image%2020230712005432.png)

将`sbin/acos_service`拖进IDA进行分析，找到解析`start`参数的位置

![](images/Pasted%20image%2020230712010302.png)

通过对httpd字符串交叉引用，发现httpd启动在sub_147B8中的sub_1226C函数中。

![](images/Pasted%20image%2020230712010422.png)

