问题描述见3.1：[arXiv:cs/9905014v1 [cs.LG] 21 May 1999](https://arxiv.org/pdf/cs/9905014.pdf)

进入`deep-reinforcement-learning/lab-taxi` 目录，运行
```
python3 main.py
```

![](images/Pasted%20image%2020230422233422.png)

## 出现的问题
### texi-v2 is is deprecated 或 No module named 'gym'
卸载现有`gym` ，安装`gym==0.14` 
```
pip uninstall gym
pip install gym==0.14
```