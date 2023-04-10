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



