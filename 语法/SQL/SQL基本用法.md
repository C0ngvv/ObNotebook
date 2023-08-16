## SELECT
查询所有语句
```sql
SELECT * FROM table_name;
```

查询指定列
```sql
SELECT column1, column2, ... FROM table_name;
```

获取唯一不同的值DISTINCT
```sql
SELECT DISTINCT column1, column2, ... FROM table_name;
```

获取前n列数据
```sql
# MySQL
SELECT column_name(s) FROM table_name LIMIT number;
# SQL Server/MS Access
SELECT TOP number|percent column_name(s) FROM table_name;
# example
select device_id from user_profile limit 2;
select device_id from user_profile limit 0,2;
select device_id from user_profile where id <=2;
```
