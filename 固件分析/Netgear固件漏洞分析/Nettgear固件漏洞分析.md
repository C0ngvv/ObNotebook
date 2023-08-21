## CVE-2020-27867
类型：命令注入
漏洞程序：mini_httpd->setup.cgi

命令位于`setup.cgi`程序`sub_407C80`程序中，读取`funjsq_access_token`参数后直接拼接到命令字符串中执行。

![](images/Pasted%20image%2020230821094354.png)

`sub_407C80`是通过映射得到的，对于`funjsq_login`。

![](images/Pasted%20image%2020230821104018.png)

在main函数中，会获取传入的`todo`，存在才调用`CallActionByName()`，`CallActionByName()`路由映射关系，依次判断映射表和`todo`内容是否一样，一样就调用相应处理函数。

![](images/Pasted%20image%2020230821104730.png)

![](images/Pasted%20image%2020230821104715.png)

疑惑的是mini_httpd是如何触发到setup.cgi程序的呢？通过对漏洞关键字`funjsq_access_token`进行查找发现下面这条链：basic_wait.htm->basic_home.htm->basic.js->funjsq.htm。basic_wait.htm是一个到basic_home.htm的跳转，asic_home.htm里面使用了basic.js，basic.js`click_action()`中在`id == "funjsq"`时调用了`goto_formframe('funjsq.htm');`，funjsq.htm发起请求。而`id="funjsq"`index.htm中设置的一个菜单选项“游戏加速器”，点击会调用`click_action("funjsq")`。

前端静态页面里有很多`@***#`（如`@post_par#`）这样的东西，这应该是占位的，传到mini_httpd程序中进行解析用相应的值进行替换再返回给客户端。








