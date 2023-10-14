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
docker-compse.yml文件和debug目录中的一样，配置网络和端口转发，Dockerfile内容有变：


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

run_clean.sh脚本内容：
```
#!/bin/sh

/run_setup.sh

/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /GREENHOUSE_BGLOG 2>&1

/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh qemu_run.sh
while true; do /greenhouse/busybox sleep 100000; done
```

奇怪，为什么感觉CMD命令和ENTRYPOINT脚本中的命令有重合，为什么要写两次？

## 手动执行仿真
首先执行下面命令，可以直接仿真成功
```
sudo chroot . greenhouse/busybox sh /run_clean.sh
```

然后尝试执行下面命令，访问不了web服务
```sh
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
# 或
sudo chroot . ./qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /bin/sh /qemu_run.sh
```

![](images/Pasted%20image%2020231014220044.png)

![](images/Pasted%20image%2020231014220107.png)

这中间的差别似乎就在于没用执行run_setup.sh进行/dev相关的配置，尝试执行下面指令，结果还是和原来一样不行。
```
sudo chroot . greenhouse/busybox sh
/run_setup.sh
/qemu-arm-static -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

然后把最后一条命令换成这个就可以了，真是奇怪。
```
/qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

于是尝试这样运行，发现也是可以的，看来不是/dev的问题（但是不知道/dev配置对仿真有没有什么影响）。
```
sudo chroot . ./qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

![](images/Pasted%20image%2020231014221423.png)

这一系列参数的作用是什么，询问ChatGPT得到答案如下：
```
-qemu-arm-static：这是一个模拟ARM环境的静态二进制文件，它会在其后面跟随的命令中执行，并以模拟ARM环境的方式运行命令。

-hackbind：该选项将宿主机的目录和模拟环境的目录进行绑定，以便在ARM程序中访问宿主机上的文件。

-hackproc：该选项用于模拟ARM环境中进程的创建情况，避免因不同架构带来的兼容性问题。

-hacksysinfo：该选项用于模拟ARM环境中的系统信息，使得ARM程序可以正常地访问和查询系统相关信息。

-execve：该选项用于替代默认的execve系统调用，以支持特殊的环境变量和选项设置。

-E LD_PRELOAD="libnvram-faker.so"：该选项设置了一个名为LD_PRELOAD的环境变量，并将值设置为"libnvram-faker.so"，这个环境变量会告诉执行的程序在执行时需要加载指定的共享库。
```

我的理解是，-hackbin、-hackproc、-hacksyinfo设置目录、proc和系统信息等，使其更好的仿真，-evecve将execve替换为"/qemu-arm-static -hackbind -hackproc -hacksysinfo"，后面就是正常的仿真参数。
```
sudo chroot . ./qemu-arm-static -hackbind -hackproc -hacksysinfo -execve "/qemu-arm-static -hackbind -hackproc -hacksysinfo" -E LD_PRELOAD="libnvram-faker.so" /usr/sbin/httpd  -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
```

看起来这几个参数很厉害，加上去之后之前仿真不起来的也能直接仿真起来，但是之前从来都没见过有人这么用。经过查阅发现，这应该不是原来qemu-arm-static里面的参数，而是作者patch后的。项目位于：[SEFCOM/GHQEMU5 (github.com)](https://github.com/sefcom/ghqemu5)

这几个参数的准确作用如下：
- hackdev/proc，复制/dev和/proc的内容，hack openat()系统调用来从那读
- hackbind，强制ipv6绑定ipv4上的0.0.0.0
- execve：添加一个参数，该参数指定 qemu-user-static 二进制文件的绝对路径，用于解决方法和调用，以便它们使用相同的 QEMU-user-static 二进制文件和传入相同的参数（否则，它默认为主机的 QEMU，即使安装了binfmt工具也可能导致问题）到`system()``execve()`
- hacksys：始终指示正在使用0个 CPU 资源的解决方法，以绕过由于系统限制而导致的行为更改，尤其是在模糊测试时

syscall.c文件

![](images/Pasted%20image%2020231014224711.png)

syscall.c第3161行

```c
/* do_socket() Must return target values and target errnos. */
static abi_long do_socket(int domain, int type, int protocol)
{
    int target_type = type;
    int ret;

    ret = target_to_host_sock_type(&type);
    if (ret) {
        return ret;
    }

    if (domain == PF_NETLINK && !(
#ifdef CONFIG_RTNETLINK
         protocol == NETLINK_ROUTE ||
#endif
         protocol == NETLINK_KOBJECT_UEVENT ||
         protocol == NETLINK_AUDIT)) {
        return -TARGET_EPROTONOSUPPORT;
    }

    /* GREENHOUSE PATCH */
    if (hackbind && domain == AF_INET6) {
        // handle all ipv6 networking as ipv4
        domain = AF_INET;
    }


    if (domain == AF_PACKET ||
        (domain == AF_INET && type == SOCK_PACKET)) {
        protocol = tswap16(protocol);
    }

    ret = get_errno(socket(domain, type, protocol));
    if (ret >= 0) {
        ret = sock_flags_fixup(ret, target_type);
        if (type == SOCK_PACKET) {
            /* Manage an obsolete case :
             * if socket type is SOCK_PACKET, bind by name
             */
            fd_trans_register(ret, &target_packet_trans);
        } else if (domain == PF_NETLINK) {
            switch (protocol) {
#ifdef CONFIG_RTNETLINK
            case NETLINK_ROUTE:
                fd_trans_register(ret, &target_netlink_route_trans);
                break;
#endif
            case NETLINK_KOBJECT_UEVENT:
                /* nothing to do: messages are strings */
                break;
            case NETLINK_AUDIT:
                fd_trans_register(ret, &target_netlink_audit_trans);
                break;
            default:
                g_assert_not_reached();
            }
        }
    }

    /* GREENHOUSE PATCH */
    // create_mark(FIRMFUCK, "socket\n")
    return ret;
}
```

![](images/Pasted%20image%2020231014225122.png)