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
git config --global http.proxy 'http://127.0.0.1:7890' 
git config --global https.proxy 'http://127.0.0.1:7890'
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

### 4. Dockerfile build走代理
虽然 `docker build` 的本质，也是启动一个容器，但是环境会略有不同，用户级配置无效。在构建时，需要注入 `http_proxy` 等参数。

```bash
docker build . \ --build-arg "HTTP_PROXY=http://proxy.example.com:8080/" \ --build-arg "HTTPS_PROXY=http://proxy.example.com:8080/" \ --build-arg "NO_PROXY=localhost,127.0.0.1,.example.com" \ -t your/image:tag
```

**注意**：无论是 `docker run` 还是 `docker build`，默认是网络隔绝的。如果代理使用的是 `localhost:3128` 这类，则会无效。这类仅限本地的代理，必须加上 `--network host` 才能正常使用。而一般则需要配置代理的外部IP，而且代理本身要开启 Gateway 模式。

重启生效

```
sudo systemctl daemon-reload 
sudo systemctl restart docker
```

参考：[如何优雅的给 Docker 配置网络代理](https://cloud.tencent.com/developer/article/1806455)

### 5.Dockerfile apt改国内源
在里面加上
```
RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
RUN sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
```

参考：[如何在dockerfile中将apt-get源更换为中国国内源](https://www.cnblogs.com/chentiao/p/17352748.html)

## hexo d部署问题
hexo d进行部署时报无法访问错误，需要设置代理：
```
# set proxy
git config --global http.proxy http://127.0.0.1:7890
git config --global https.proxy https://127.0.0.1:7890
# unset proxy
git config --global --unset http.proxy
git config --global --unset https.proxy
```