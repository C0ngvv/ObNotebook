安装预编译版本，访问[LLVM Download Page](https://releases.llvm.org/download.html) 查看下载版本

```
cd /usr/local
sudo wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.1/clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
sudo tar xvf clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz
sudo mv clang+llvm-13.0.1-x86_64-linux-gnu-ubuntu-18.04.tar.xz llvm-13.0.1
export PATH="$PATH:/usr/local/llvm-13.0.1/bin"
```

然后就可以使用了
```
clang -v
```

