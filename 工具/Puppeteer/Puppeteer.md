## 环境安装

```
pip install pyppeteer
```


之前装的

![](images/Pasted%20image%2020231114162830.png)

但是安装后打开Chromium是一篇空白，没有页面没有按钮。

![](images/Pasted%20image%2020231114163206.png)

换个下载：https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64/970501/chrome-linux.zip，然后就可以了。

## 爬取
### 登录弹窗认证
Netgear登录抓包，在http报文中有一个认证。

![](images/Pasted%20image%2020231114203200.png)

可以使用puppeteer的`page.authenticate()`来实现，其中Credentials接口有两个属性：`username`和`password`。

![](images/Pasted%20image%2020231114203548.png)

代码
```python
await page.authenticate({'username':'admin','password':'password'})
await page.goto(root_url)
```

当页面跳转导航到其它URL时，可以使用`page.waitForNavigation()`。

