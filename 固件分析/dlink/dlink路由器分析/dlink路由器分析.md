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

后来发现