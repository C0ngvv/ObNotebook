## 页面请求分析
通过FirmAE对路由器进行仿真，然后使用burpsuite进行抓包，发现dlink的请求都为/HNAP1，而请求数据为xml格式。

```xml
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/xml
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
SOAPACTION: "http://purenetworks.com/HNAP1/SetPortForwardingSettings"
HNAP_AUTH: D02A7DBD402FCAE983FD68751EDEFD8A 1700641872
Content-Length: 653
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/PortForwarding.html
Cookie: uid=m0hsAU1zNU

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Body>
		<SetPortForwardingSettings>
			<PortForwardingList>
				<PortForwardingInfo>
					<Enabled>true</Enabled>
					<PortForwardingDescription>a</PortForwardingDescription>
					<TCPPorts>40</TCPPorts>
					<UDPPorts>40</UDPPorts>
					<LocalIPAddress>192.168.0.2</LocalIPAddress>
					<ScheduleName>Always</ScheduleName>
				</PortForwardingInfo>
			</PortForwardingList>
		</SetPortForwardingSettings>
	</soap:Body>
</soap:Envelope>
```

```xml
POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/xml
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/xml
SOAPACTION: "http://purenetworks.com/HNAP1/SetSysLogSettings"
HNAP_AUTH: 2EB837617C02EA2C4CD6C983A2B607B3 1700642114
Content-Length: 400
Origin: http://192.168.0.1
Connection: close
Referer: http://192.168.0.1/SystemLog.html
Cookie: uid=m0hsAU1zNU

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Body>
		<SetSysLogSettings xmlns="http://purenetworks.com/HNAP1/">
			<SysLog>true</SysLog> 
			<IPAddress>192.168.0.2</IPAddress>
		</SetSysLogSettings>
	</soap:Body>
</soap:Envelope>
```

后来发现在`etc/services/HTTP/httpcfg.php`文件中设置了`HNAP1`，可以看到它实际是由`/usr/sbin/hnap`处理。

![](images/Pasted%20image%2020231122213357.png)

而`/usr/sbin/hnap`实际上是`htdocs/cgibin`程序的软连接，即所有的http请求由cgibin处理。

![](images/Pasted%20image%2020231122213647.png)

在dir815路由器中，GET页面请求的为php文件，POST页面请求的为/hedwig.cgi。

## xmldb分析
在dlink路由器中，有很多xmldbc操作。“`xmldbc` 是一种基于 XML 的数据格式，用于描述和存储设备的配置信息和操作指令。”

![](images/Pasted%20image%2020231123232858.png)

在xmldbc_set中，有如下操作。会建立unix套接字，连接/var/run/xmldb_sock，然后通过send等方法发送数据。

![](images/Pasted%20image%2020231123233357.png)

经查找发现存在/usr/sbin/xmldb程序，将其拖入IDA进行分析。

