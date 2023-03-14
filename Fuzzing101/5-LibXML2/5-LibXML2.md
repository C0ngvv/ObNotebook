## 环境配置
下载所需环境
```
cd /home/fuzzing101
mkdir fuzzing_libxml2 && cd fuzzing_libxml2

wget http://xmlsoft.org/download/libxml2-2.9.4.tar.gz
tar zxf libxml2-2.9.4.tar.gz && cd libxml2-2.9.4/
```

构建libxml2
```
sudo apt-get install python3-dev
CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-fsanitize=address" CXXFLAGS="-fsanitize=address" LDFLAGS="-fsanitize=address" ./configure --prefix="/home/fuzzing101/Fuzzing_libxml2/libxml2-2.9.4/install" --disable-shared --without-debug --without-ftp --without-http --without-legacy --without-python LIBS='-ldl'
make -j$(nproc)
make install
```




