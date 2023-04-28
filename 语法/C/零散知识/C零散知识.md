
`fgets` 从指定的流 stream 读取一行，并把它存储在 **str** 所指向的字符串内。当读取 **(n-1)** 个字符时，或者读取到换行符时，或者到达文件末尾时，停止。
```c
char *fgets(char *str, int n, FILE *stream)
```

`strsep` 字符串分割，把stringp里面出现的delim替换成'\0'，后将 stringp 更新指向到'\0'符号的下一个字符地址，函数的返回值指向原来的 stringp 位置。
```
char *strsep(char **stringp, const char *delim)
```

`strncasecmp` 比较参数s1 和s2 字符串前n个字符，比较时会自动忽略大小写的差异。
```
int strncasecmp(const char *s1, const char *s2, size_t n);
```