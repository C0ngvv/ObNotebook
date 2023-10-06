```
sudo docker run -it -p 50003:22 --privileged=true -v ~/Desktop/ghShareSpace:/ghShareSpace greenhouse:usenix-eval-jul2023 /bin/bash

service ssh start
```

之前测试了几个（）都不行，后来试了RT_AC51U_3.0.0.4_380_8497_g179ec32这个可以，但可以显示web登录路由器初始设置页面，点击Apply后没反应，没有达到模糊测试的标准。

![](Greenhouse测试/images/Pasted%20image%2020230814205757.png)

![](Greenhouse测试/images/Pasted%20image%2020230814205915.png)