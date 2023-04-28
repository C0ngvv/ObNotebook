
## handle_request

首先`fgets( line, sizeof(line), conn_fp )` 获得请求第一行，对其进行解析，然后对剩余行进行解析。如果当前行为`\n`或`\r\n` ，结束解析；然后依次解析`Accept-Language:`, `Authorization:`, `User-Agent:`, `Cookie:`, `Referer:`, `Host:`, `Content-Length:`和`boundary=`。

如果方法不是`get`、`post`、`head`，就返回 501 Not Implemented。

如果请求路径开头不是`/`，返回 404 Bad filename。

获取请求文件名，简单过滤。

空时根据情况返回`QIS_default.cgi`, `find_device.asp`, `index.asp`.

提取访问的url



### mine_handler
`mime_handler` 结构体
```c
/* Generic MIME type handler */
struct mime_handler {
	char *pattern;    //接口名称
	char *mime_type;    //Accept格式
	char *extra_header;    //Cache-Control
	void (*input)(char *path, FILE *stream, int len, char *boundary);  //获取data中内容
	void (*output)(char *path, FILE *stream);    //处理函数
	void (*auth)(char *userid, char *passwd, char *realm);    //校验权限
};
```

案例如下
```c
struct mime_handler mime_handlers[] = {
	{ "Main_Login.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "Nologin.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "error_page.htm*", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "blocking.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "gotoHomePage.htm", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "ure_success.htm", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
	{ "ureip.asp", "text/html", no_cache_IE7, do_html_post_and_get, do_ej, NULL },
}
```

依次将mine_handlers中元素的pattern和url对比，若匹配就执行相关操作，若不匹配，则根据情况返回200或404 Not Found。
```c
	for (handler = &mime_handlers[0]; handler->pattern; handler++) {
		if (match(handler->pattern, url)){...}
	}
	if (!handler->pattern){...}
```

经过一系列认证等验证操作后，调用`handler->input()`执行相关操作。







nvram取消设置
```c
nvram_unset("httpd_handle_request");
nvram_unset("httpd_handle_request_fromapp");
```

起初我怀疑这个代码或许是某种同步机制，后来在`handler->pattern`和url匹配成功后处理代码发现了设置代码，所以它的作用可能就是传递变量或存储当前正在处理的请求信息。
```
nvram_set("httpd_handle_request", url);
nvram_set_int("httpd_handle_request_fromapp", fromapp);
```





