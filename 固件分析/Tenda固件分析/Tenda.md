
```
sudo brctl addbr br0
sudo brctl addif br0 ens33
sudo ifconfig br0 up
sudo dhclient br0
```

## AC23

```
sudo chroot . ./qemu-mipsel-static ./bin/httpd
```

22.04启动模拟，启动Burpsuit，启动浏览器，一访问页面系统就崩溃。