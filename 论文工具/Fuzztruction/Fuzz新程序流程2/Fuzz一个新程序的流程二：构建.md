以Funzzing101第1个案例Xpdf为例，构建Fuzztruction的对该程序模糊测试的环境。

## 流程
1. 找到一个目标程序Consumer输入的Generator程序
2. 用Fuzztruction编译工具编译Generator
3. 用AFL编译工具编译目标程序Consumer
4. 编写yml配置文件
5. 运行fuzztruction命令

需要付出的额外努力：
1. Generator的源码编译方法
2. Consumer的源码编译方法
3. Generator程序的使用方法
4. Consumer程序的使用方法

## Generator选择
这里用fuzztruction论文里用过的poppler

config.sh文件
```shell
function build_ft {
    mkdir -p ft
    mkdir -p inputs
    rm -rf ft/*
    cp -r src/poppler-0.86.1 ft/

    # build poppler
    pushd ft/poppler-0.86.1 > /dev/null

    export FT_HOOK_INS=store,load,select,icmp
    export CC=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast
    sed -i "s@^\s*CC.*@CC=$CC@g" debian/rules
    export CXX=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast++
    sed -i "s@^\s*CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -g -fPIC -ldl"
    export DEB_CXXFLAGS_SET="-v -O3 -g -fPIC"
    export DEB_LDFLAGS_SET="-fPIC -ldl"

    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"
    dpkg-buildpackage --no-sign -jauto -b

    popd > /dev/null
}
```

生成的Generator程序位于：`/home/user/fuzzTest/xpdf/ft/poppler-0.86.1/obj-x86_64-linux-gnu/utils/pdfseparate`

输入文件

## Consumer构建

```bash
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvzf xpdf-3.02.tar.gz
```

config.sh文件
```shell
function build_afl {
    mkdir -p afl
    rm -rf afl/*
    cp -r src/xpdf-3.02 afl/
    pushd afl/xpdf-3.02 > /dev/null

    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-v -O3 -g -fPIC -ldl"
    export CXXFLAGS="-v -O3 -g -fPIC"

    ./configure -prefix="/home/user/fuzzTest/xpdf/install"
    make -j
    popd > /dev/null
}
```

目标位于：`/home/user/fuzzTest/xpdf/afl/xpdf-3.02/xpdf/pdftotext`

## fuzztruction执行配置文件
`pdfseparate-pdftotext.yml`

```yml
work-directory: "/tmp/pdfseparate_pdftotext"
input-directory: "./inputs/inputs_ft"
jail-uid: 606400022
jail-gid: 606400022
timeout: 50ms

source:
    env:
        - LD_LIBRARY_PATH: "/home/user/fuzzTest/xpdf/ft/poppler-0.86.1/obj-x86_64-linux-gnu"
    bin-path: "/home/user/fuzzTest/xpdf/ft/poppler-0.86.1/obj-x86_64-linux-gnu/utils/pdfseparate"
    arguments: ["@@", "$$"]
    input-type: file
    output-type: file
    output-suffix: ".pdf"
    log-stdout: false
    log-stderr: false

sink:
    env:
        - LD_LIBRARY_PATH: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/poppler_qpdf/afl/poppler-0.86.1/obj-x86_64-linux-gnu/"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/poppler_qpdf/afl/poppler-0.86.1/obj-x86_64-linux-gnu/utils/pdftotext"
    arguments: ["@@"]
    input-type: file
    output-type: none
    log-stdout: false
    log-stderr: false
    allow-unstable-sink: true

afl++:
    input-dir: "./inputs/inputs_other"

```


