# Grammar Mutator
一个基于语法的自定义mutator，用于afl++处理高度结构化的输入。

Project: [AFLplusplus/Grammar-Mutator: A grammar-based custom mutator for AFL++ ](https://github.com/AFLplusplus/Grammar-Mutator)

## 构建语法结构
目前已有一些语法定义文件在grammars目录下，包括http.json，语法文件的更多细节在：[Grammar-Mutator/doc/customizing-grammars.md](https://github.com/AFLplusplus/Grammar-Mutator/blob/stable/doc/customizing-grammars.md)

指定语法文件使用`GRAMMAR_FILE`环境变量。

```
make GRAMMAR_FILE=grammars/ruby.json
```

### 语法文件
语法文件在 JSON 中指定，并显示为键/值对的集合。

每个键表示一个用尖括号括起来的**语法标记**，键的对应值是**语法规则列表**。

```json
{
    "<START>": [["RULE1"], ["RULE2"]]
}
```

对于每个**语法规则**，它由一个字符串列表组成，这些字符串可以代表**具体字符串**或**语法标记**。

```json
["<A>", " likes ", "<B>"]
```

给定输入语法，语法赋值器为每个输入测试用例构造树表示。 然后，将树转换为目标应用程序的具体输入。

示例，下面这个语法文件可以生成两个字符串："I like C"和"I like C++"。

```json
{
    "<A>": [["I ", "<B>"]],
    "<B>": [["like ", "<C>"]],
    "<C>": [["C"], ["C++"]]
}
```

### http.json
语法文件http.json的部分代码如下，文件位于：[Grammar-Mutator/grammars/http.json](https://github.com/AFLplusplus/Grammar-Mutator/blob/stable/grammars/http.json)
```json
{
	"<A>": [["<START_LINE>", "\r\n", "<HEADERS>", "<BODY>", "\r\n\r\n"]],
	
	"<START_LINE>": [["<METHOD>", " ", "<URI>", " ", "<VERSION>"]],
	
	"<HEADERS>": [[], ["<HEADER>", "\r\n", "<HEADERS>"]],
	
	"<HEADER>": [["<HEADER_FIELD>", ": ", "<ANY>"]],
	
	"<HEADER_FIELD>": [["A-IM"], ["Accept"], ["Accept-Charset"], ["Accept-Datetime"], ["Accept-Encoding"], ["Accept-Language"], ["Access-Control-Request-Method"], ["Access-Control-Request-Headers"], ["Authorization"], ["Cache-Control"], ["Connection"], ["Content-Encoding"], ["Content-Length"], ["Content-MD5"], ["Content-Type"], ["Cookie"], ["Date"], ["Expect"], ["Forwarded"], ["From"], ["Host"], ["HTTP2-Settings"], ["If-Match"], ["If-Modified-Since"], ["If-None-Match"], ["If-Range"], ["If-Unmodified-Since"], ["Max-Forwards"], ["Origin"], ["Pragma"], ["Proxy-Authorization"], ["Range"], ["Referer"], ["TE"], ["Trailer"], ["Transfer-Encoding"], ["User-Agent"], ["Upgrade"], ["Via"], ["Warning"]],
	
	"<BODY>": [[], ["<CHAR>"]],

	"<CHAR>": [["0"], ["1"], ["2"], ["3"], ["4"], ["5"], ["6"], ["7"], ["8"], ["9"], ["a"], ["b"], ["c"], ["d"], ["e"], ["f"], ["g"], ["h"], ["i"], ["j"], ["k"], ["l"], ["m"], ["n"], ["o"], ["p"], ["q"], ["r"], ["s"], ["t"], ["u"], ["v"], ["w"], ["x"], ["y"], ["z"], ["A"], ["B"], ["C"], ["D"], ["E"], ["F"], ["G"], ["H"], ["I"], ["J"], ["K"], ["L"], ["M"], ["N"], ["O"], ["P"], ["Q"], ["R"], ["S"], ["T"], ["U"], ["V"], ["W"], ["X"], ["Y"], ["Z"]]
}
```

## 使用
将项目下载下来
```bash
git clone https://github.com/AFLplusplus/Grammar-Mutator.git
```

安装工具包
```bash
sudo apt install valgrind uuid-dev default-jre python3
wget https://www.antlr.org/download/antlr-4.8-complete.jar
sudo cp -f antlr-4.8-complete.jar /usr/local/lib
```
### 构建
进入到项目目录中，编写语法规则，这里使用grammar/http.json，然后构建
```
make GRAMMAR_FILE=grammars/http.json
```

![](images/Pasted%20image%2020231113144817.png)

运行完后，src目录就会出现两个文件：`libgrammarmutator-http.so`和`grammar_generator-http`，前者用于AFL++模糊测试，后者用于生成该规则的种子。

### 模糊测试
进行模糊测试时，只需要设置`AFL_CUSTOM_MUTATOR_LIBRARY`和`AFL_CUSTOM_MUTATOR_ONLY`环境变量即可。
```
export AFL_CUSTOM_MUTATOR_LIBRARY=./libgrammarmutator-http.so
export AFL_CUSTOM_MUTATOR_ONLY=1
afl-fuzz -m 128 -i seeds -o out -- /path/to/target @@
```

### 可能出现的问题
若出现这个问题，可能是因为目录下的`third_party/antlr4-cpp-runtime/antlr4-cpp-runtime-4.8-source.zip`文件没有成功下载下来，可以手动下载一下，目录下的Readme有下载连接。

![](images/Pasted%20image%2020231113145006.png)