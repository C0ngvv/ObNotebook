从官网下载R6250固件，版本为1.0.4.48。

## httpd程序启动

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

## http请求解析
Netgear前端点击按钮后会发送cgi请求

![](images/Pasted%20image%2020230712114307.png)

![](images/Pasted%20image%2020230712114326.png)

对于的httpd程序中的cgi程序会处理

![](images/Pasted%20image%2020230712114403.png)

![](images/Pasted%20image%2020230712114430.png)

前端页面由数字组成按钮，并设置点击事件，该数字应该通过某种方式映射为对应的cgi请求。

![](images/Pasted%20image%2020230712114507.png)

## NVRAM分析
### nvram_init
将`usr/lib/libnvram.so` 拖进IDA进行分析，首先看`nvram_init()`函数。它的操作是通过open打开`/dev/nvram` 并将文件描述符赋给`dword_1349C`，打开成功后采用mmap分配空间，然后使用fcntl()进行设置。

![](images/Pasted%20image%2020230712220730.png)

### acosNvramConfig_set
acosNvramConfig_set->j_nvram_set->nvram_set->nvram_set_0,这几个函数都是相同的。在nvram_set_0中，首先调用j_nvram_init()进行初始化（j_nvram_init->nvram_init，已进行过初始化会直接返回0），然后分配一段缓冲区来临时存储设置的key value值，如果value存在则存储形式为"key=value"，否则只保存"key"，最后将缓冲区内容写入nvram文件描述符。

![](images/Pasted%20image%2020230712221602.png)

### acosNvramConfig_get
acosNvramConfig_get->j_nvram_get->nvram_get

![](images/Pasted%20image%2020230712222414.png)

### acosNvramConfig_match
获取key相应的value，然后和第二个参数比较是否一致。

![](images/Pasted%20image%2020230712222533.png)



