`set -u` 如果遇到不存在的变量，Bash 默认忽略它

`set -e` 只要发生错误，就终止执行，不适用于管道命令

所谓管道命令，就是多个子命令通过管道运算符（|）组合成为一个大的命令。Bash 会把最后一个子命令的返回值，作为整个命令的返回值。也就是说，只要最后一个子命令不失败，管道命令总是会执行成功，因此它后面命令依然会执行，set -e就失效了。

`set -o pipefail` 用来解决这种情况，只要一个子命令失败，整个管道命令就失败，脚本就会终止执行

`set -x`用来在运行结果之前，先输出执行的那一行命令

`cd $(dirname $0)` 获取shell脚本所在目录的绝对路径

`dirname`的功能是去掉文件路径名中的从右往左数的第一个`/`及其之后的所有文字。`$0`，这是bash shell脚本中的位置参数

if判断
```shell
-b file     Checks if file is a block special file; if yes, then the condition becomes true.    [ -b $file ] is false.
-c file     Checks if file is a character special file; if yes, then the condition becomes true.    [ -c $file ] is false.
-d file     Checks if file is a directory; if yes, then the condition becomes true.     [ -d $file ] is not true.
-f file     Checks if file is an ordinary file as opposed to a directory or special file; if yes, then the condition becomes true.  [ -f $file ] is true.
-g file     Checks if file has its set group ID (SGID) bit set; if yes, then the condition becomes true.    [ -g $file ] is false.
-k file     Checks if file has its sticky bit set; if yes, then the condition becomes true.     [ -k $file ] is false.
-p file     Checks if file is a named pipe; if yes, then the condition becomes true.    [ -p $file ] is false.
-t file     Checks if file descriptor is open and associated with a terminal; if yes, then the condition becomes true.  [ -t $file ] is false.
-u file     Checks if file has its Set User ID (SUID) bit set; if yes, then the condition becomes true.     [ -u $file ] is false.
-r file     Checks if file is readable; if yes, then the condition becomes true.    [ -r $file ] is true.
-w file     Checks if file is writable; if yes, then the condition becomes true.    [ -w $file ] is true.
-x file     Checks if file is executable; if yes, then the condition becomes true.  [ -x $file ] is true.
-s file     Checks if file has size greater than 0; if yes, then condition becomes true.    [ -s $file ] is true.
-e file     Checks if file exists; is true even if file is a directory but exists.  [ -e $file ] is true.
```

https://www.tutorialspoint.com/unix/unix-basic-operators.htm


