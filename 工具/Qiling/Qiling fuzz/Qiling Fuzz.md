Qiling框架extensions中写了一个afl.py，是对unicornafl.uc_afl_fuzz一些常用逻辑的wrapper，可以在qiling脚本中调用ql_afl_fuzz设置模糊测试配置，但真正跑起来模糊测试还是得安装AFLplusplus，用afl-fuzz命令行行启动。

## 1.环境安装
Qiling环境安装，这个命令是安装最新的dev版本。
```bash
pip3 install --user https://github.com/qilingframework/qiling/archive/dev.zip
```

AFLplusplus环境安装
```bash
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make
cd ./unicorn_mode
./build_unicorn_support.sh
```