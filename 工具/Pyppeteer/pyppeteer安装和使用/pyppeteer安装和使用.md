

## 环境安装

```
pip install pyppeteer
```

之前装的

![](images/Pasted%20image%2020231114162830.png)

但是安装后打开Chromium是一篇空白，没有页面没有按钮。

![](images/Pasted%20image%2020231114163206.png)

换个下载：https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/Linux_x64/970501/chrome-linux.zip，然后就可以了。

## API
API参考：[API Reference — Pyppeteer 0.0.25 documentation](https://pyppeteer.github.io/pyppeteer/reference.html)
### Page
该类提供了与 Chrome 浏览器的单个tab进行交互的方法。一个浏览器对象可能有多个Page对象。

#### authenticate()
提供http的authentication，参数`credentials`应该是`None`或包含`username`和`password`域的字典。
```
authenticate(credentials: Dict[str, str]) → Any
```

#### evaluate()
在浏览器中执行js函数或js表达式并获得结果。
```
evaluate(pageFunction: str, *args, force_expr: bool = False) → Any
```

参数：
- `pageFunction(str)`: 在浏览器中执行的js函数或表达式字符串
- `force_expr(bool)`: 如果为 True，则将 pageFunction 作为表达式进行执行。如果为 False（默认值），则尝试自动检测函数或表达式。

#### mainFrame
获取页面的main Frame

#### type()
向匹配selector的元素写入text(模拟用户输入)，没有匹配的元素就抛出异常PageError。
```
type(selector: str, text: str, options: dict = None, **kwargs) → None
```

- 元素选择器：`elementname`
- id选择器：`#idname`
- class选择器：`.classname`
- 属性选择器：`[attr] [attr=value]`
### Frame
#### childFrmaes
Get child frames.

#### querySelectorAll()
Get all elements which matches`selector`.
```
querySelectorAll(selector: str) → List[pyppeteer.element_handle.ElementHandle]
```

