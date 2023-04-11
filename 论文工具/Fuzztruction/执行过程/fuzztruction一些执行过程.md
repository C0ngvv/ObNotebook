向Generator注入错误的目的？

不依赖于重量级的程序分析技术和粗粒度的语法近似或专家知识，生成具有高度复杂格式的输入。这样的数据可以绕过目标程序初始解析状态，执行更深的程序路径。

以有目标的方式变异Generator



## 生成端与消费端
消费端Consumer是我们要测试的目标程序，使用Fuzztruction进行测试时需要提供一个生成端Generator用来生成Consumer的输入。

Consumer为`pdftotext` 程序\["@@"\]，Generator为`pdfsepqrate` 程序\["@@", "\$\$"\]。



Generator用Fuzztruction的编译工具源码编译，以实现后续对Generator变异。Consumer用AFL++编译工具编译，来获取覆盖率信息。


