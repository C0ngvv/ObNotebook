
提取特定文本内容s
```python
text = 'POST /goform/SetFirewallCfg HTTP/1.1\n'
url = re.findall('\S+\s+(\S)\s+HTTP/1.1', text)
```


`\s`:匹配任何空白字符
`\S`:匹配任何非空白字符