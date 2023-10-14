# Greenhouse Patch结果分析
以`AC1450_V1.0.0.6_1.0.3.chk`为例对Greenhouse工具跑出的结果进行分析，看一下docker是如何启动固件的，然后尝试不利用docker直接启动。

## 生成的文件分析
生成的文件目录如下：

![](images/Pasted%20image%2020231014212256.png)

### config.json
config.json文件里描述了关于这个设备仿真时的相关信息
```json
{
      "image": "AC1450_V1.0.0.6_1.0.3.chk",
      "hash": "eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995",
      "brand": "netgear",
      "result": "SUCCESS",
      "seconds_to_up": 204.39599227905273,
      "targetpath": "/usr/sbin/httpd",
      "targetip": "172.21.0.2",
      "targetport": "80",
      "ipv6enable": true,
      "env": {
            "LD_PRELOAD": "libnvram-faker.so"
      },
      "workdir": "/",
      "background": [
            [
                  "/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve \"/qemu-arm-static -hackbind -hackproc -hacksysinfo \" -E LD_PRELOAD=\"libnvram-faker.so\" /bin/sh /run_background.sh",
                  1
            ],
            [
                  "/run_setup.sh",
                  1
            ]
      ],
      "loginuser": "admin",
      "loginpassword": "password",
      "loginurl": "http://172.21.0.2:80",
      "logintype": "basic",
      "loginheaders": {
            "User-Agent": "python-requests/2.24.0",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="
      },
      "loginpayload": "",
      "qemuargs": {
            "hackbind": "",
            "hackproc": "",
            "hacksysinfo": "",
            "execve": "/qemu-arm-static -hackbind -hackproc -hacksysinfo"
      }
}
```
### debug目录
然后看debug目录，看Dockerfile文件内容如下，就是将fs拷贝到Ubuntu中然后执行run.debug.sh脚本。
```
FROM ubuntu:20.04
RUN apt-get update && apt-get -y install vim curl
COPY fs /fs
CMD ["./fs/run_debug.sh"]
```

查看docker-compose.yml文件，主要是配置网络和端口转发。

```yml
version: "2.2"

services:
  gh_rehosted:
    build: .
    privileged: true
    networks:
      eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge0:
        ipv4_address: 172.21.0.2
      eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge1:
        ipv4_address: 192.168.1.5
      eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge2:
        ipv4_address: 192.168.2.5
    ports:
      - 80:80/tcp
      - 80:80/udp
      - 81:81/tcp
      - 81:81/udp
      - 443:443/tcp
      - 443:443/udp

networks:
   eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge0:
     driver: bridge
     ipam:
       config:
       - subnet: 172.21.0.0/24
         gateway: 172.21.0.1
   eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge1:
     driver: bridge
     ipam:
       config:
       - subnet: 192.168.1.0/24
         gateway: 192.168.1.1
   eca65ffc2bb1cfcb0dec6cd8d467a1db0d4979d54f983cda51637846cc1bb995ghbridge2:
     driver: bridge
     ipam:
       config:
       - subnet: 192.168.2.0/24
         gateway: 192.168.2.1
```

现在我们看fs中的启动脚本run_debug.sh，主要执行三个脚本：`run_setup.sh`，`run_background.sh`, `qemu_run.sh`。
```sh
#!/bin/sh
chroot /fs /run_setup.sh

chroot fs /qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /fs/GREENHOUSE_BGLOG 2>&1

chroot fs /qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /qemu_run.sh

while true; do sleep 10000; done
```

run_setup.sh脚本内容主要是执行setup_dev.sh脚本，这个脚本是设置/dev的一些配置。
```sh
#!/bin/sh
/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev
```

run_background.sh对于很多固件来说都是空的，暂不讨论。最后的qemu_run.sh脚本就是httpd的启动脚本。
```sh
/usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

所以总结起来就是，运行docker后运行run_debug.sh脚本，这个脚本依次运行`run_setup.sh`，`run_background.sh`, `qemu_run.sh`，功能就是先配置/dev，然后启动httpd程序。

### minimal目录
docker-compse.yml文件和debug目录中的一样，配置网络和端口转发，Dockerfile内容有变，

```
FROM scratch
ADD fs /

ENV LD_PRELOAD=libnvram-faker.so

EXPOSE 80/tcp
EXPOSE 80/udp
EXPOSE 1900/tcp
EXPOSE 1900/udp

ENTRYPOINT ["/greenhouse/busybox", "sh", "/run_clean.sh"]

CMD ["qemu-arm-static", "--", "/usr/sbin/httpd", "-S", "-E", "/usr/sbin/ca.pem", "/usr/sbin/httpsd.pem"]
```