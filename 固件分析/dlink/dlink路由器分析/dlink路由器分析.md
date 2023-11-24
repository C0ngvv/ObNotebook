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

经查找发现存在/usr/sbin/xmldb程序，还有/usr/sbin/xmldbc程序，而该程序是上面xmldb程序的软连接。将其拖入IDA进行分析。

在main方法中，根据调用的程序名有两个处理，当文件名为xmldbc时调用xmldbc_main，而当文件名为xmldb时调用xmldb_main。而关于/var/run/xmldb_sock的启动就在xmldb_main中。

![](images/Pasted%20image%2020231124085349.png) 

进入后进行一些设置操作，然后最主要的是调用了sub_4023A0()。

![](images/Pasted%20image%2020231124090021.png)

在sub_4023A0()中的主要代码如下，这段代码主要就是创建套接字监听。其中name为全局遍历，表示/var/run/xmldb_sock，首先创建这个文件，然后建立unix类型socket，bind绑定该文件，然后开启listen。

Unix socket不经过网络传输，用于同一主机不同进程间通信，其与网络socket使用上无区别，只是在绑定服务器标识时，网络socket使用IP和端口号，而Unix socket使用文件路径名标识，即/var/run/xmldb_sock。

![](images/Pasted%20image%2020231124091017.png)

后续的操作在sloop中，首先sloop_init()进行初始化操作，然后sloop_register_signal()注册信号处理操作，最后sloop_run()执行主循环操作，但没看太懂在做什么。

![](images/Pasted%20image%2020231124093113.png)

grep寻找启动命令
```
./etc/init.d/S20init.sh:xmldb -n $image_sign -t > /dev/console &
```

![](images/Pasted%20image%2020231124105022.png)



## 启动分析
首先etc/init.d/rcS，该脚本依次执行init.d目录下脚本，最终执行etc/init0.d/rcS脚本。init0.d/rcS主要执行/etc/scripts/dbload.sh脚本从数据库中加载配置信息，然后遍历/etc/init0.d/S??下脚本，依次执行start命令。

