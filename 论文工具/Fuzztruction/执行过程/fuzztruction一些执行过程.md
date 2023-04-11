
## 生成端与消费端
消费端Consumer是我们要测试的目标程序，使用Fuzztruction进行测试时需要提供一个生成端Generator用来生成Consumer的输入。

Consumer为`pdftotext` 程序\["@@"\]，Generator为`pdfsepqrate` 程序\["@@", "\$\$"\]。



Generator用Fuzztruction的编译工具源码编译，以实现后续对Generator变异。Consumer用AFL++编译工具编译，来获取覆盖率信息。
