**向Generator注入错误的目的？**

不依赖于重量级的程序分析技术和粗粒度的语法近似或专家知识，生成具有高度复杂格式的输入。这样的数据可以绕过目标程序初始解析状态，执行更深的程序路径。

以有目标的方式变异Generator，使其生成满足复杂格式约束的半有效输出。

**如何变异？与对输入直接变异相比，为什么这种变异不会对程序结构破坏？**

Generator程序的处理逻辑没有改变，所以生成文件的结构的各个部分还是正确的，只是各个部分的数据可能会变异。

**隐式知识**
题目中Leverage Implicit Domain Knowledge中的隐式领域知识是指程序员编码在Generator程序里生成数据处理逻辑，根据这个逻辑可以生成格式正确的输出。

文件的结构正确但每个结构内的数据可能有变异从而绕过解析，或者数据处理具有一定流程，Fuzztruction对前面数据变异后，因为它的处理逻辑没有改变，变异后的数据可以按正确的逻辑生成输出，这样就可以绕过一些验证阶段达到更深的路径。

> 例如，假设我们将错误注入到操作（即，读或写）部分处理的数据的指令中，这些数据随后将被加密签名。 在这种情况下，我们可以产生关于包络签名的变异但有效的输入。 至关重要的是，这些输入不会在签名验证期间早期丢弃，而是到达消费者中更深层次的程序逻辑。 

## 生成端与消费端
消费端Consumer是我们要测试的目标程序，使用Fuzztruction进行测试时需要提供一个生成端Generator用来生成Consumer的输入。

Consumer为`pdftotext` 程序\["@@"\]，Generator为`pdfsepqrate` 程序\["@@", "\$\$"\]。

### objcopy_objdump
#### objdump
objdump命令是Linux下的反汇编目标文件或者可执行文件的命令，它以一种可阅读的格式让你更多地了解二进制文件可能带有的附加信息。
```
objdump [选项] objfile...
```
参数：\["-S", "@@"\]

功能：将代码段反汇编的同时，将反汇编代码与源代码交替显示

#### objcopy
Generator程序使用**objcopy**，它将目标文件的一部分或者全部内容拷贝到另外一个目标文件中，或者实现目标文件的格式转换。
```
objcopy [选项]... 输入文件 [输出文件]
```
参数：\["--strip-all", "-g", "--strip-unneeded", "--weaken" , "-D", "@@", "\$\$"\]

说明：
- `--strip-all` : 不从源文件拷贝符号信息和 relocation 信息。
- `-g` : 不从源文件拷贝调试符号信息和相关的段。
- `--strip-unneeded` : 去掉所重定位处理不需要的符号
- `--weaken` : 将所有全局符号转变为弱符号
- `-D` : 在确定性模式下操作。在复制存档成员和写入存档索引时，uid、gid、时间戳使用0，并对所有文件使用一致的文件模式。

输入文件为二进制程序

### objcopy_readelf
#### readelf
用于显示 `elf` 格式文件的信息。

参数：`["-a", "-W", "-I", "-z", "-D", "-c", "-n", "-u", "-g", "@@"]`

#### objcopy
参数：`["--strip-all", "-g", "--strip-unneeded", "--weaken" , "-D", "@@", "$$"]`

输入文件：elf, pe程序

### mke2fs_e2fsck
#### e2fsck
用于检查使用 Linux ext2 档案系统的 partition 是否正常工作。

```
    arguments: ["-p", "-f", "@@"]
    input-type: file
    output-type: stdout
```

#### mke2fs
用于建立ext2文件系统

```
    arguments: ["-t", "ext4", "@$"]
    input-type: file
    output-type: file
```

输入：data文件

### pngtopng_pngtopng
#### pngtopng消费器
```
    arguments: ["@@", "/dev/null"]
    input-type: file
    output-type: file
```

#### pngtopng生成器
```
    arguments: ["@@", "$$"]
    input-type: file
    output-type: file
```

输入：png文件

### zip_unzip
#### unzip
```
    arguments: ["-p", "-P", "PASSWORD", "@@"]
    input-type: file
    output-type: None
```

#### zip
```
    arguments: ["-e", "-P", "PASSWORD", "-1", "$$", "@@"]
    input-type: file
    output-type: file
    output-suffix: ".zip"
```

输入文件：文本和二进制程序

### 7zip-7zip
#### 7z 消费端
```
    arguments: ["e", "-so", "-y", "@@"]
    input-type: file
    output-type: None
```
- `e` 命令解压，不会保持目录结构，会把所有的文件都解压到目的目录下

#### 7z 生成端
```
    arguments: ["a", "-t7z", "-mx=1", "-ms=off", "-m0=LZMA", "-mhe=off", "-si", "-y", "$$"]
    input-type: stdin
    output-type: file
```
- `a` 添加文件到压缩包中

### 7zip-enc_7zip-dec
#### 7z 消费端
```
    arguments: ["e", "-so", "-y", "-pPASSWORD", "@@"]
    input-type: file
    output-type: None
```

#### 7z 生成端
```
    arguments: ["a", "-pPASSWORD", "-si", "-y", "$$"]
    input-type: stdin
    output-type: file
```

### sign-vfychain
#### vfychain
验证工具vfychain可以验证证书链。
```
    arguments: ["-a", "@@"]
    input-type: file
    output-type: None
```

#### openssl
```
    arguments: ["req", "-x509", "-new", "-key", "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/sign_vfychain/sigkey.key", "-subj", "/CN=ABC", "-sha256", "-outform", "der", "-out", $$]
    input-type: none
    output-type: file
```

### gendsa-dsa
#### openssl消费端
```
    arguments: ["dsa", "-in", "@@", "-passin", "pass:xxxx"]
    input-type: file
    output-type: None
```

#### openssl生成端
```
    arguments: ["gendsa", "-passout", "pass:xxxx", "-des", "-out", "$$", "/home/user/fuzztruction/fuzztruction-experiments/comparison-with-state-of-the-art/configurations/gendsa_dsa/dsaparm_8bit"]
    input-type: none
    output-type: file
```

### genrsa_rsa
#### openssl消费端
```
    arguments: ["rsa", "-check", "-in", "@@", "-passin", "pass:xxxx"]
    input-type: file
    output-type: None
```
- `rsa` RSA密钥管理

#### openssl生成端
```
    arguments: ["genrsa", "-passout", "pass:xxxx", "-aes128", "-out", "$$", "512"]
    input-type: none
    output-type: file
```
- `genrsa` 生成RSA私钥
- `-passout pass:xxxx` 指定output密码


传递

Generator用Fuzztruction的编译工具源码编译，以实现后续对Generator变异。Consumer用AFL++编译工具编译，来获取覆盖率信息。


