## CVE-2020-27867
类型：命令注入
漏洞程序：setup.cgi

命令位于`setup.cgi`程序`sub_407C80`程序中，读取`funjsq_access_token`参数后直接拼接到命令字符串中执行。

![](images/Pasted%20image%2020230821094354.png)











