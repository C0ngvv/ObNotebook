
## 关注点：
1.构建测试目标程序Consumer
2.构建目标程序输入生成器Generator
3.编写Fuzztruction配置文件

## 配置文件分析
### build.sh
检测配置文件是否存在，根据参数构建程序。
```shell
path = $1
# 判断目录是否存在
cfg_path = "$path/config.sh"
# 判断目录下是否存在config.sh文件
cd $path
source config.sh

check_config_exported_functions  # 检测config.sh配置文件函数是否完整

然后根据参数调用config.sh声明的函数，构建模糊测试所需的程序
```

config.sh文件包含以下函数，用于对各种模糊工具构建环境，有价值的应该只有build_ft
```
build_ft
build_afl
build_symcc
build_afl_symcc
build_vanilla
install_dependencies
get_source
```

`get_source` 代码，下载源码到src目录
```shell
function get_source {
    mkdir -p src
    pushd src > /dev/null
    git clone https://github.com/glennrp/libpng.git --depth 1 || true
    pushd libpng > /dev/null
    git checkout libpng16
    popd > /dev/null
    popd > /dev/null
}
```

`build_ft` 所做的工作，使用fuzztruction 编译器编译构建源码在ft目录下
```shell
function build_ft {
    mkdir -p inputs    # 创建目录 input
    mkdir -p ft        # 创建目录 ft ，并清空目录里面内容
    rm -rf ft/*        
    cp -r src/libpng ft/  # 递归复制源码 src/libpng 到 ft/
    pushd ft/libpng > /dev/null

    export FT_HOOK_INS=store,load,select,icmp   # 定义插桩的指令
    export CC=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast
    export CXX=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast++
    export CFLAGS="-v -O3 -fPIC -ldl"
    export CXXFLAGS="-v -O3 -fPIC"
    export LDFLAGS="-fPIC -ldl"
    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null
    popd > /dev/null
}
```

`build_aft` 用于构建afl 测试环境，同时也是构建fuzztruction的Consumer
```shell
function build_afl {
    mkdir -p afl
    rm -rf afl/*
    cp -r src/libpng afl/
    pushd afl/libpng > /dev/null

    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-v -O3 -g -fPIC -ldl"
    export CXXFLAGS="-v -O3 -g -fPIC"

    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null
    popd > /dev/null
}
```

## fuzztruction配置文件
配置文件为`yml` 文件
### 基本配置信息
```yml
work-directory: "所有模糊测试数据的存储目录，它应该位于/tmp目录下"
input-directory: "Generator的输入, 不需要消耗数据的情况这必须是一些文件"
jail-uid: 606400022 # user用户的IDs
jail-gid: 606400022
timeout: 50ms
```

### Generator配置信息
```yml
source:
	bin-path: "指向Generator二进制程序文件"
	arguments: ["@@", "$$"] # @@为输入文件路径，$$为输出文件路径
	input-file: file  # 输入文件类型：file, stdin, none
	output-type: file # 输出文件类型：file, stdin, none
	log-stdout: false
    log-stderr: false
```

### Consumer配置信息
```yml
sink:
    bin-path: "执行Consumer二进制程序"
    arguments: ["@@", "/dev/null"]
    input-type: file
    output-type: file
    log-stdout: false
    log-stderr: false
    # Whether to add unstable (inputs with varying coverage) to the queue.
    allow-unstable-sink: true  
```

## 完整文件
### build.sh文件
```shell
#!/usr/bin/env bash

set -eu
set -o pipefail

function in_subshell () {
    (
        $1
    )
}

function check_config_exported_functions() {
    local failed=0
    for fn_name in "get_source install_dependencies build_ft build_afl build_symcc build_afl_symcc build_vanilla"; do
        if ! type $fn_name > /dev/null; then
            echo "[!] Target config does not define function $fn_name"
            failed=1
        fi
    done
    if [[ $failed -ne 0 ]]; then
        echo "[!] Config check failed! Please fix your config."
        exit 1
    fi
}

if [[ $# -lt 1 ]]; then
    echo "[!] Not enough arguments! TODO: <path> [mode]"
    exit 1
fi

path=$1
if [[ ! -d "$path" ]]; then
    echo "[!] Invalid directory: $path"
    exit 1
fi
cfg_path="$path/config.sh"
if [[ ! -f "$cfg_path" ]]; then
    echo "[!] Config could not be found at: $cfg_path"
    exit 1
fi

cd $path
source config.sh
check_config_exported_functions


mode=${2-"all"}
case $mode in
    source|src)
        in_subshell get_source
    ;;
    deps)
        in_subshell install_dependencies
    ;;
    ft)
        in_subshell build_ft
    ;;
    afl)
        # This binary will be used by WEIZZ as well
        in_subshell build_afl
    ;;
    symcc)
        in_subshell build_symcc
        in_subshell build_afl_symcc
    ;;
    vanilla)
        in_subshell build_vanilla
    ;;
    all)
        in_subshell get_source || true
        in_subshell install_dependencies || true
        in_subshell build_ft || true
        in_subshell build_afl || true
        in_subshell build_symcc || true
        in_subshell build_afl_symcc || true
        in_subshell build_vanilla || true
    ;;
    *)
        echo "[!] Invalid mode $mode"
        exit 1
    ;;
esac
```

### libpng-config.sh源文件
```shell
#!/usr/bin/env bash

set -eu

function build_ft {
    mkdir -p inputs
    mkdir -p ft
    rm -rf ft/*
    cp -r src/libpng ft/
    pushd ft/libpng > /dev/null

    export FT_HOOK_INS=store,load,select,icmp
    export CC=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast
    export CXX=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast++
    export CFLAGS="-v -O3 -fPIC -ldl"
    export CXXFLAGS="-v -O3 -fPIC"
    export LDFLAGS="-fPIC -ldl"
    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null
    popd > /dev/null
}

function build_afl {
    mkdir -p afl
    rm -rf afl/*
    cp -r src/libpng afl/
    pushd afl/libpng > /dev/null

    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-v -O3 -g -fPIC -ldl"
    export CXXFLAGS="-v -O3 -g -fPIC"

    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null

    popd > /dev/null
}

function build_symcc {
    mkdir -p symcc
    rm -rf symcc/*
    cp -r src/libpng symcc/
    pushd symcc/libpng > /dev/null

    export SYMCC_NO_SYMBOLIC_INPUT=yes
    export CC="/symcc/symcc"
    export CXX="/symcc/sym++"
    export CFLAGS="-v -O3 -g -fPIC -ldl"
    export CXXFLAGS="-v -O3 -g -fPIC"

    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null

    popd > /dev/null
}

function build_afl_symcc {
    mkdir -p afl_symcc
    rm -rf afl_symcc/*
    cp -r src/libpng afl_symcc/
    pushd afl_symcc/libpng > /dev/null

    export AFL_LLVM_INSTRUMENT="CLASSIC"
    export AFL_MAP_SIZE=65536
    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1
    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    export CFLAGS="-v -O3 -g -fPIC -ldl"
    export CXXFLAGS="-v -O3 -g -fPIC"

    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null

    popd > /dev/null
}

function build_vanilla {
    mkdir -p vanilla
    rm -rf vanilla/*
    cp -r src/libpng vanilla/
    pushd vanilla/libpng > /dev/null
    export CC="gcc"
    ./configure
    make -j
    pushd contrib/examples > /dev/null
    $CC pngtopng.c -Wl,-rpath $(readlink -f ../../.libs) -L $(readlink -f ../../.libs) -lpng16 -o pngtopng
    popd > /dev/null
    popd > /dev/null
}

function install_dependencies {
    echo "No dependencies"
}

function get_source {
    mkdir -p src
    pushd src > /dev/null
    git clone https://github.com/glennrp/libpng.git --depth 1 || true
    pushd libpng > /dev/null
    git checkout libpng16
    popd > /dev/null
    popd > /dev/null
}
```

### pngtopng-pngtopng.yml 文件
```yml
# Directory where all fuzzing data is stored. It should be located in the /tmp directory
# since file system operations considerably slow down Fuzztruction.
# You should consider resizing/tmp and back it by addition swap since the directory
# can grow quite large.
work-directory: "/tmp/pngtopng_pngtopng"
# Inputs passed to the generator. For applications not consuming any data, this must be some file; thus Fuzztruction stops
# to complain.
input-directory: "./inputs_ft"
# IDs of the user `user` (retrieved via `id`). They are used as the target ids for dropping privileges for child processes.
jail-uid: 606400022
jail-gid: 606400022
timeout: 50ms

# The generator configuration.
source:
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/ft/libpng/contrib/examples/pngtopng"
    # @@: Path to the input file.
    # $$: Path to the output file.
    arguments: ["@@", "$$"]
    # Type of input: file, stdin, none
    input-type: file
    # Type of output: file, stdout
    output-type: file
    log-stdout: false
    log-stderr: false

# The consumer configuration.
sink:
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/afl/libpng/contrib/examples/pngtopng"
    arguments: ["@@", "/dev/null"]
    input-type: file
    output-type: file
    log-stdout: false
    log-stderr: false
    # Whether to add unstable (inputs with varying coverage) to the queue.
    allow-unstable-sink: true

# AFL++ configuration (optional)
afl++:
    # Inputs used by AFL++ to fuzz the consumer.
    input-dir: "./inputs_other"

# SYMCC configuration (optional)
symcc:
    # Custom environment variables for the target. It can also be used for the source, sink, afl++, and vanilla sections.
    # This is mostly  used to set LD_PRELOAD; thus the loader loads the instrumented libraries instead of the ones installed
    # in the system's search path. Please see other `YAML` files for examples,
    env:
        - NONE: "None"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/symcc/libpng/contrib/examples/pngtopng"
    # SYMCC needs a custom afl++ binary, thus we need a separate config entry here.
    afl-bin-env:
        - NONE: "None"
    afl-bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/afl_symcc/libpng/contrib/examples/pngtopng"

# Vanilla binary (uninstrumented), used for coverage computation and fuzzing via WEIZZ.
vanilla:
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/libpng/vanilla/libpng/contrib/examples/pngtopng"
    
```

### unzip-config.sh源文件
```shell
#!/usr/bin/env bash

set -eu

readonly ZIP_VERSION="3.0"
readonly ZIP_TARGET="zip-$ZIP_VERSION"
readonly UNZIP_VERSION="6.0"
readonly UNZIP_TARGET="unzip-$UNZIP_VERSION"
readonly LIBBZ2_VERSION="1.0"


function build_ft {
    mkdir -p inputs
    mkdir -p ft
    rm -rf ft/*

    # build libbz2
    cp -r src/libbz2/* ft/
    pushd ft/bzip2-${LIBBZ2_VERSION}* > /dev/null

    export FT_HOOK_INS=store,load,select,icmp
    export CC=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast
    export CXX=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast++
    sed -i "s@^\s*CC.*@CC=$CC@g" debian/rules
    sed -i "s@^\s*CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -g -fPIC -ldl"
    export DEB_CXXFLAGS_SET="-v -O3 -g -fPIC"
    export DEB_LDFLAGS_SET="-fPIC -ldl"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null

    # build zip
    cp -r src/zip/* ft/
    pushd ft/$ZIP_TARGET > /dev/null
    find "$PWD" -iname "*.c" -exec sed -i 's@.*signal(.*handler).*@/* signal call removed */@g' {} \;

    export FT_HOOK_INS=store,load,select,icmp
    export CC=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast
    sed -i "s@^CC.*@CC=$CC@g" debian/rules
    export CXX=/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast++
    sed -i "s@^CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -g -fPIC -ldl"
    export DEB_CXXFLAGS_SET="-v -O3 -g -fPIC"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null
}

function build_afl {
    mkdir -p afl
    rm -rf afl/*
    cp -r src/unzip/* afl/
    pushd afl/$UNZIP_TARGET > /dev/null
    find "$PWD" -iname "*.c" -exec sed -i 's@.*signal(.*handler).*@/* signal call removed */@g' {} \;

    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1

    export CC="afl-clang-fast"
    sed -i "s@^CC.*@CC=$CC@g" debian/rules
    export CXX="afl-clang-fast++"
    sed -i "s@^CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null

    # build libbz2
    cp -r src/libbz2/* afl/
    pushd afl/bzip2-${LIBBZ2_VERSION}* > /dev/null

    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1

    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    sed -i "s@^\s*CC.*@CC=$CC@g" debian/rules
    sed -i "s@^\s*CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null
}

function build_symcc {
    mkdir -p symcc
    rm -rf symcc/*
    cp -r src/unzip/* symcc/
    pushd symcc/$UNZIP_TARGET > /dev/null
    find "$PWD" -iname "*.c" -exec sed -i 's@.*signal(.*handler).*@/* signal call removed */@g' {} \;

    export SYMCC_NO_SYMBOLIC_INPUT=yes
    export SYMCC_LIBCXX_PATH=/libcxx_symcc
    export CC="/symcc/symcc"
    sed -i "s@^CC.*@CC=$CC@g" debian/rules
    export CXX="/symcc/sym++"
    sed -i "s@^CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null

    # build libbz2
    cp -r src/libbz2/* symcc/
    pushd symcc/bzip2-${LIBBZ2_VERSION}* > /dev/null

    export SYMCC_NO_SYMBOLIC_INPUT=yes
    export SYMCC_LIBCXX_PATH=/libcxx_symcc
    export CC="/symcc/symcc"
    export CXX="/symcc/sym++"
    sed -i "s@^\s*CC.*@CC=$CC@g" debian/rules
    sed -i "s@^\s*CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null
}

function build_afl_symcc {
    mkdir -p afl_symcc
    rm -rf afl_symcc/*
    cp -r src/unzip/* afl_symcc/
    pushd afl_symcc/$UNZIP_TARGET > /dev/null
    find "$PWD" -iname "*.c" -exec sed -i 's@.*signal(.*handler).*@/* signal call removed */@g' {} \;

    export AFL_LLVM_INSTRUMENT="CLASSIC"
    export AFL_MAP_SIZE=65536
    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1

    export CC="afl-clang-fast"
    sed -i "s@^CC.*@CC=$CC@g" debian/rules
    export CXX="afl-clang-fast++"
    sed -i "s@^CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null

    # build libbz2
    cp -r src/libbz2/* afl_symcc/
    pushd afl_symcc/bzip2-${LIBBZ2_VERSION}* > /dev/null

    export AFL_LLVM_INSTRUMENT="CLASSIC"
    export AFL_MAP_SIZE=65536
    export AFL_LLVM_LAF_SPLIT_SWITCHES=1
    export AFL_LLVM_LAF_TRANSFORM_COMPARES=1
    export AFL_LLVM_LAF_SPLIT_COMPARES=1

    export CC="afl-clang-fast"
    export CXX="afl-clang-fast++"
    sed -i "s@^\s*CC.*@CC=$CC@g" debian/rules
    sed -i "s@^\s*CXX.*@CXX=$CXX@g" debian/rules || true
    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null
}

function build_vanilla {
    mkdir -p vanilla
    rm -rf vanilla/*
    cp -r src/unzip/* vanilla/
    pushd vanilla/$UNZIP_TARGET > /dev/null
    find "$PWD" -iname "*.c" -exec sed -i 's@.*signal(.*handler).*@/* signal call removed */@g' {} \;

    export CC="clang"
    sed -i "s@^CC.*@CC=$CC@g" debian/rules
    export CXX="clang++"
    sed -i "s@^CXX.*@CXX=$CXX@g" debian/rules || true

    export DEB_CFLAGS_SET="-v -O3 -fPIC -g -ldl -DNO_EXCEPT_SIGNALS"
    export DEB_CXXFLAGS_SET="-v -O3 -fPIC -g -DNO_EXCEPT_SIGNALS"
    export DEB_LDFLAGS_SET="-fPIC -ldl"
    export DEB_BUILD_OPTIONS="nodocs nostrip nocheck nomult nocross nohppa"

    dpkg-buildpackage --no-sign -j -b
    popd > /dev/null
}

function install_dependencies {
    export DEBIAN_FRONTEND=noninteractive
    # zip (source)
    sudo apt build-dep zip=${ZIP_VERSION} -y
    # unzip (sink)
    sudo apt build-dep unzip=${UNZIP_VERSION} -y
    # libbz2 (library used for compression)
    sudo apt build-dep libbz2-1.0=${LIBBZ2_VERSION} -y
}

function get_source {
    mkdir -p src
    # download zip (source)
    mkdir -p src/zip
    pushd src/zip > /dev/null
    export DEBIAN_FRONTEND=noninteractive
    apt source zip=${ZIP_VERSION} -y
    popd > /dev/null
    # download unzip (sink)
    mkdir -p src/unzip
    pushd src/unzip > /dev/null
    apt source unzip=${UNZIP_VERSION} -y
    popd > /dev/null
    # download libbz2 (library used for compression)
    mkdir -p src/libbz2
    pushd src/libbz2 > /dev/null
    apt source libbz2-1.0=${LIBBZ2_VERSION} -y
    popd > /dev/null
}
```

### zip-unzip.yml
```yml
# zip with encryption and then unzip.

work-directory: "/tmp/zip_unzip"
input-directory: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/zip_unzip/inputs_ft"
jail-uid: 606400022
jail-gid: 606400022
timeout: 50ms

source:
    env:
        - LD_LIBRARY_PATH: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/ft/bzip2-1.0.8"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/ft/zip-3.0/zip"
    arguments: ["-e", "-P", "PASSWORD", "-1", "$$", "@@"]
    input-type: file
    output-type: file
    output-suffix: ".zip"
    log-stdout: false
    log-stderr: false

sink:
    env:
        - LD_LIBRARY_PATH: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/afl/bzip2-1.0.8/debian/tmp/lib"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/afl/unzip-6.0/unzip"
    arguments: ["-p", "-P", "PASSWORD", "@@"]
    input-type: file
    output-type: None
    log-stdout: false
    log-stderr: false
    allow-unstable-sink: true

afl++:
    input-dir: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/zip_unzip/inputs_other"

symcc:
    env:
        - LD_LIBRARY_PATH: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/symcc/bzip2-1.0.8/debian/tmp/lib"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/symcc/unzip-6.0/unzip"
    afl-bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/afl_symcc/unzip-6.0/unzip"
    afl-bin-env:
        - LD_LIBRARY_PATH: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/afl_symcc/bzip2-1.0.8/debian/tmp/lib"

vanilla:
    env:
        - LD_LIBRARY_PATH: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/vanilla/unzip-6.0/unzip"
    bin-path: "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/binaries/unzip/vanilla/unzip-6.0/unzip"
```