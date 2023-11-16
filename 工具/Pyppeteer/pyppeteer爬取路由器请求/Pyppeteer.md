API参考：[API Reference — Pyppeteer 0.0.25 documentation](https://pyppeteer.github.io/pyppeteer/reference.html)
## 环境安装

```
pip install pyppeteer
```


之前装的

![](images/Pasted%20image%2020231114162830.png)

但是安装后打开Chromium是一篇空白，没有页面没有按钮。

![](images/Pasted%20image%2020231114163206.png)

换个下载：https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64/970501/chrome-linux.zip，然后就可以了。

## 算法思路
针对页面元素分类：
1. 输入：input
2. 按钮：label, button
3. 链接：a

- 对于输入，读取属性，对其进行填充
- 对于按钮，读取属性，进行点击
- 对于链接，读取属性，进行跳转然后递归搜索这三个元素，注意url去重

其它，form表单识别等。


## 爬取
### 登录弹窗认证
Netgear登录抓包，在http报文中有一个认证。

![](images/Pasted%20image%2020231114203200.png)

可以使用puppeteer的`page.authenticate()`来实现，其中Credentials接口有两个属性：`username`和`password`。

![](images/Pasted%20image%2020231115090002.png)

代码
```python
await page.authenticate({'username':'admin','password':'password'})
await page.goto(root_url)
```

当页面跳转导航到其它URL时，可以使用`page.waitForNavigation()`。

现在的问题：Netgear页面URL不变，始终为start.html，使用waitForNavigation()好像会报错，不使用页面加载不出来。

### iframe
Netgear路由器页面显示所采用的是一个iframe，如图所示。左边的选项列表注册了event，当用户点击时，就将相应url(保存在a标签)传递到iframe的src进行加载。

![](images/Pasted%20image%2020231116084940.png)

所以如何让其加载iframe内容并对iframe进行爬取成为爬取Netgear页面的挑战点。当我们用page.click()后，页面并没有加载出来，而调用page.waitForNavigation()后可以加载出来但随后会抛出异常，可能因为网页url没有改变。加载出来页面后，因为改变的是iframe，所以我们又需要到iframe中去获取。

```
frame = page.frames[0]
```

研究半天，最后发现是因为加载需要延时，使用sleep()让它加载几秒它就出来了。
```python
await asyncio.sleep(3)
# 或
frame = page.frames[1]
await frame.waitForSelector('body')
await asyncio.sleep(2)
```

pytteteer解析的Netgear页面的frames有3个，其中frames\[0]为mainFrame，frames\[1]为BASIC页面的iframe，frames\[2]为ADVANCED页面的iframe。

**初始页面加载模块**。包括登录和页面加载，使当前页面和状态处于爬虫的起始位置。

当前页面包含的frame有：mainframe，主要包含链接标签；frames\[1]主要是BASIC功能页面，里面包含一些设置等。

调研：在BASIC页面时，frames\[2]是否有内容；在ADVANCED页面时，frames\[1]是否有内容。

经过调查，点击ADVANCED页面时，BASIC页面的内容依然保存在页面中，只是上层div设置`display:None`，点击BASIC页面时同样如此。即我们不能直接遍历frames解析所有的内容，因为这样会重复解析。

注意到，在iframe中包含了src属性，即显示的页面url，我们可以通过该属性来判断次iframe是否为我们当前加载的iframe，如果是就进行解析，如果不是则不进行解析。并且经过调查，对mainFrame查询并不会得到childFrame的结果，因此是可行的。

```
page.mainFrame.childFrames[0].url
```

Netgear爬取算法设计
```
页面登录
初始页面加载
读取frame的标签链接和按钮表单等
	case 1 按钮表单：
		自动输入，提交
	case 2 标签链接：
		点击，等待
		定位响应链接的frame
		调用此函数递归分析frame
```