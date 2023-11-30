# ftool
a simple frida tool for mac

## 0x01 使用方法

`python/python3 ftool.py`

![image-20231130105111336](assets/image-20231130105111336.png)

## 0x02 命令

命令调用如果包含参数，使用`:`隔开

显示相关基础命令

- `n`上一个
- `m`下一个
- `t`开头
- `b`结尾
- `exit`退出

Frida操作命令

- `hook:<target>`frida附加进程，`target`可以是应用名或者pid
- `list`列举当前附加的frida客户端
- `set:<client_id>`设置当前命令执行客户端，client_id可以通过`list`获取
- `exec:<cmd>`对当前frida客户端进行执行js代码，如果cmd为`exit`，frida客户端会退出
- `execf:<js_file>`对frida客户端进行执行指定文件中的js代码

![iShot_2023-11-30_11.29.10](assets/iShot_2023-11-30_11.29.10.gif)
