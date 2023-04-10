
需求：
1.构建测试目标程序Consumer
2.构建目标程序输入生成器Generator
3.编写Fuzztruction配置文件


### build.sh

```shell
path = $1
# 判断目录是否存在
cfg_path = "$path/config.sh"
# 判断目录下是否存在config.sh文件
cd $path
source config.sh

check_config_exported_functions  # 检测config.sh配置文件函数是否完整

```

config.sh文件包含函数，用于对各种模糊工具构建环境，有价值的应该只有build_ft
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


build.sh文件
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

config.sh源文件
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