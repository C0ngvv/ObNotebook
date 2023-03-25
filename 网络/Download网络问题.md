## Linux代理
设置代理
```
export http_proxy=http://127.0.0.1:7890
export https_proxy=http://127.0.0.1:7890
export no_proxy="localhost, 127.0.0.1"
```

取消代理
```
unset http_proxy
unset https_proxy
unset no_proxy
```

搜索代理进程
```
ps -ef | grep clash
kill 进程号
```

## Git代理
设置代理
```
git config --global http.proxy 'socks5://127.0.0.1:1080' 
git config --global https.proxy 'socks5://127.0.0.1:1080'
```

取消代理
```
git config --global --unset http.proxy
git config --global --unset https.proxy
```

## Docker
### 1.使用镜像源
```
vim /etc/docker/daemon.json

# 内容如下：
{
  "registry-mirrors": [
    "https://xx4bwyg2.mirror.aliyuncs.com",
    "http://f1361db2.m.daocloud.io",
    "https://registry.docker-cn.com",
    "http://hub-mirror.c.163.com",
    "https://docker.mirrors.ustc.edu.cn"
  ]
}{}

# 退出并保存
:wq

# 使配置生效
systemctl daemon-reload

# 重启Docker
systemctl restart docker
```

### 2.设置dockerd服务走代理
创建 `/etc/systemd/system/docker.service.d/proxy.conf` 配置文件:
 ```
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:7890"
Environment="HTTPS_PROXY=https://127.0.0.1:7890"
Environment="NO_PROXY=127.0.0.1"
```

然后重新加载配置并重启服务:
```
systemctl daemon-reload
systemctl restart docker
```

然后检查加载的配置:
```
systemctl show docker --property Environment
```

### 3.Dockerfile From慢
如果Dockerfile build时里面From镜像太大又慢还卡，可以先在构建前先用docker pull把镜像拉下来，再build。
```
sudo docker pull '镜像'
```


