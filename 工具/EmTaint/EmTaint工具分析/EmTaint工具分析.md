## 使用方法
### 环境安装
其中EmTaint.tar.gz位于其上传的谷歌云中。
```
docker pull doneme123/emtaint:v1.1
tar -zxvf EmTaint.tar.gz
cd EmTaint
docker run -ti --rm -v `pwd`:/work doneme123/emtaint:v1.1
cd /work
workon EmTaint
```




## /data/ida_data/router/文件分析
### httpd_block_info.json
没完全看懂
```
{
	函数块地址1:{},
	函数块地址2:{
		"块地址？？？":[
			[
				LDR地址|变量间接引用地址,
				解析变量地址,
				类型(func_ptr, iCall, ext_data, )
			],
			...
		]
	},
	...
}
```

### httpd_cfg.json
```
{
	函数块地址：{
		"jmp调用图":[
			[
				前一个块地址，
				后一个块地址
			],
			[
				前一个块地址，
				后一个块地址
			],
			...
		],
		"call函数调用":[
			[
				所在块地址,
				调用函数处地址,
				调用的函数名
			],
			...
		],
		"name函数名": "sub_372EC",
		"block自上到下函数块":[
			[
				函数块1地址,
				函数块2地址
			],
			[
				函数块2地址,
				函数块3地址
			],
			...
		]
	}
}
```

## /data/result_data/router_version.json
对结果文件进行分析
```
{
	"buffer_overflow":{
		"危险调用位置地址":{
			"name调用的危险函数": "sprintf",
			"offset危险参数栈上偏移":[
				90
			],
			"info": [
				?,
				?,
				?,
				?
			],
			"func所在的函数":462088
		}
	}
}
```