
提取特定文本内容s
```python
text = 'POST /goform/SetFirewallCfg HTTP/1.1\n'
req = re.findall('(POST|GET)\s+(\S+)\s+HTTP/1.1.*', text)
# req = [('GET', '/goform/SetFirewallCfg')]
```


`\s`:匹配任何空白字符

`\S`:匹配任何非空白字符

`\d`:匹配数字0-9

`\D`:匹配非数字

`\w`:匹配单次字符a-zA-Z0-9_

`\W`:匹配非单次字符

匹配多个字符串并保存：`(POST|GET)`

匹配多个字符串但不保存：`(?:POST|GET)`

[(181条消息) 【Python技巧】正则表达式：（?:）匹配多个字符串之一；（非获取匹配）_python正则匹配多个字符串_你别说了多动脑子的博客-CSDN博客](https://blog.csdn.net/weixin_49340599/article/details/127515668)

