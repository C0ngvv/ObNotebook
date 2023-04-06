安装预编译版本，访问[LLVM Download Page](https://releases.llvm.org/download.html) 查看下载版本

```
cd /usr/local
sudo wget https://github.com/llvm/llvm-project/releases/download/llvmorg-16.0.0/clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
sudo tar xvf clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz
sudo mv clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04 llvm-16.0
export PATH="$PATH:/usr/local/llvm-16.0/bin"
```

然后就可以使用了
```
clang -v
```

