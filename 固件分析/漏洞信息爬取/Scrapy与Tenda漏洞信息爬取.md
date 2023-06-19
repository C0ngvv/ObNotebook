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

