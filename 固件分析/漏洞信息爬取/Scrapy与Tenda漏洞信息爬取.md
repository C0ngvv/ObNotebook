## Scrapy安装与使用
```shell
pip install --upgrade pip
pip install Scrapy
```

创建项目
```
scrapy startproject tendaVuls
```

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

## 参考链接
[(178条消息) Python Scrapy多层爬取收集数据_kocor的博客-CSDN博客](https://blog.csdn.net/ygc123189/article/details/79160146)