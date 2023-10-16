## 环境配置
### 取消sudo密码
```bash
sudo visudo
# 改为`%sudo ALL=(ALL) NOPASSWD: ALL`
# 该行含义为 用户 组=(用户:组) NOPASSWD: 允许执行无需密码的程序
```


```bash
sudo apt-get install vim
sudo apt-get install git
sudo apt-get install bridge-utils
sudo apt install net-tools
sudo apt install python3-pip
sudo apt install curl
sudo apt install binwalk

# QEMU
sudo apt-get install qemu
sudo apt-get install qemu-system
sudo apt-get install qemu-user
sudo apt-get install qemu-user-static
sudo apt install gdb-multiarch
```

## 镜像源
## apt
[ubuntu | 镜像站使用帮助 | 清华大学开源软件镜像站 | Tsinghua Open Source Mirror](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/)

### pip
```
# vim  ~/.pip/pip.conf
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
[install]
trusted-host = https://pypi.tuna.tsinghua.edu.cn
```

## ssh
开启ssh远程登录
```
sudo apt install openssh-server
sudo systemctl status ssh
# 或
sudo service ssh status
sudo service ssh start
sudo service ssh restart
```

编辑配置文件`/etc/ssh/sshd_config`，允许root登录，设置以下选项：
```
PermitRootLogin yes
PasswordAuthentication yes
```

## pwngdb/pwngdb
[GitHub - pwndbg/pwndbg: Exploit Development and Reverse Engineering with GDB Made Easy](https://github.com/pwndbg/pwndbg)

```
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

[GitHub - scwuaptx/Pwngdb: gdb for pwn](https://github.com/scwuaptx/Pwngdb)

```
cd ~/
git clone https://github.com/scwuaptx/Pwngdb.git 
cp ~/Pwngdb/.gdbinit ~/
```

将pwngdb/pwngdb路径加入.gdbinit中，加在最前面

```
source /home/ubuntu/pwndgb/gdbinit.py
```

![](images/Pasted%20image%2020230616153731.png)

[(176条消息) gdb调试 | pwndbg+pwndbg联合使用_fmtarg__n19hT的博客-CSDN博客](https://blog.csdn.net/weixin_43092232/article/details/105648769)
## java jdk
### apt安装
```
sudo apt install openjdk-8-jdk   # 安装 Java 1.8
sudo apt install openjdk-11-jdk  # 安装 Java 11
```

使用`update-alternatives`管理多个java版本
```
update-alternatives --config java
```

### 压缩包安装
下载jdk17，我下载的版本为17.0.7:[Java Downloads | Oracle](https://www.oracle.com/java/technologies/downloads/#java17)

然后解压，复制到`/usr/local/`目录下

```shell
tar -zxvf jdk-17_linux-x64_bin.tar.gz
sudo cp -r jdk-17.0.7/ /usr/local/
```

编辑`/etc/profile` 配置环境变量

```sh
# sudo vim /etc/profile
export JAVA_HOME=/usr/local/jdk-17.0.7
export CLASSPATH=.:$JAVA_HOME/lib
export PATH=.:$JAVA_HOME/bin:$JAVA_HOME/lib:$PATH
```

然后`source /etc/profile`。

参考：[Ubuntu Linux 安装配置JDK17开发环境_webrx的博客-CSDN博客](https://blog.csdn.net/webrx/article/details/120678805)

## Burpsuit
文件下载
1. 安装java jdk17(17.0.7)，见上文；
2. 下载注册机(v1.15)：[Releases · h3110w0r1d-y/BurpLoaderKeygen (github.com)](https://github.com/h3110w0r1d-y/BurpLoaderKeygen/releases)
3. 下载BrupSuite JAR(2023.6):[Burp Suite Release Notes (portswigger.net)](https://portswigger.net/burp/releases)

> 推荐放在/opt/ 目录下

运行注册机BurpLoaderKeygen.jar文件
```
java -jar BurpLoaderKeygen.jar
```

![](images/Pasted%20image%2020230613100826.png)

点击Run就会启动Burpsuit，然后将License复制到Burpsuit上

![](images/Pasted%20image%2020230613100913.png)

然后点手动激活Manual activation，Copy request到上方Activation Request，然后将Activation Reponse自动生成的内容复制到下方的Paste response，然后Next。

![](images/Pasted%20image%2020230613101104.png)

![](images/Pasted%20image%2020230613101218.png)

启动方式(在BurpLoaderKeygen.jar启动后的界面上有)

```
"/usr/local/jdk-17.0.7/bin/java" "--add-opens=java.desktop/javax.swing=ALL-UNNAMED" "--add-opens=java.base/java.lang=ALL-UNNAMED" "--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED" "--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED" "--add-opens=java.base/jdk.internal.org.objectweb.asm.Opcodes=ALL-UNNAMED" "-javaagent:/home/ubuntu/Burpsuit/BurpLoaderKeygen.jar" "-noverify" "-jar" "/home/ubuntu/Burpsuit/burpsuite_pro_v2023.6.jar" 
```

将此内容创建写入文件burpsuite中，添加+x可执行权限，然后执行就可运行
```
./burpsuite
```

创建软连接使能够直接运行
```
sudo cp burpsuite /usr/bin/burpsuite
```

参考链接：[Burpsuite Pro 2023.3.2破解 - yxchun - 博客园 (cnblogs.com)](https://www.cnblogs.com/ychun/p/17391122.html)

## wireshark

```
sudo apt install wireshark
```

安装过程中选择Yes允许非超级用户捕获数据包。

![](images/Pasted%20image%2020230614164122.png)

安装完后运行命令`wireshark`即可运行，但需要`sudo`才能捕获ens33等接口。
```
sudo wireshark
```

## maven
### apt安装
```
sudo apt install maven
```

在ubuntu20.04上安装的版本为3.6.3，不支持Java17。

修改镜像源，在`~/.m2/`目录下创建`settings.xml`文件，将文件内容[settings.xml](https://files-cdn.cnblogs.com/files/chenyanbin/settings.xml)写入或覆盖。

