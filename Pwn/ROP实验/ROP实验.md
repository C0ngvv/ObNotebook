## 任意写
向任意内存地址rw写入内容"/bin/sh"。

需要寻找往内存中写入数据的gadget
```
ROPgadget --binary dhcp.bin --only "mov|ret"
```


