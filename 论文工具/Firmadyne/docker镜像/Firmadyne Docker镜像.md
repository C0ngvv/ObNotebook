使用的是该镜像
```
sudo docker pull mborgerson/firmadyne:auto
sudo docker run -it -v /home/cxw/firmadyne:/share mborgerson/firmadyne:auto /bin/bash
sudo chown -R firmadyne:firmadyne /share
```

退出后再进入命令
```
sudo docker start 4b
sudo docker exec -it 4b /bin/bash
```

firmadyne目录下内容
![](images/Pasted%20image%2020230414090140.png)

