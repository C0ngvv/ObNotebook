这篇文章介绍使用AFL++模糊套接字的二进制文件。

为使用AFL++进行模糊测试，程序必须接收来自文件的输入。因此我们需要进行二进制水平的修改，通过patch汇编指令和`LD_PRELOAD` 技巧。Github上的[desockmulti](https://github.com/zyingp/desockmulti?ref=blog.attify.com)项目可以用于这个目的。

在使用这个[desockmulti](https://github.com/zyingp/desockmulti?ref=blog.attify.com) 前，我们需要进行一下修改。`httpd`二进制程序目前使用daemon函数fork到后台，在模糊测试期间，我们并不需要这个fork行为。

![](images/Pasted%20image%2020230507223855.png)

我们需要覆写`daemon`，使其在不fork 的情况下实际返回0。这可以通过LD_PRELOAD或patch汇编指令来实现。

我们需要做的另一个改变是让httpd在退出前只处理一个请求（不像一般的网络服务器那样无限期地处理请求）。这样，我们就可以知道哪个请求（如果有的话）会使网络服务器崩溃。

要关闭一个socket，`httpd`调用`close`函数。有三个地方调用close。









