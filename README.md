# ftool
a simple frida tool for mac

工具目前只适用在macos上使用，目前存在或多或少的小问题，只作为调试使用，输出内容建议结合生成的log文件查看。

## 0x01 使用方法

`python/python3 ftool.py`

![image-20231130105111336](assets/image-20231130105111336.png)

## 0x02 命令

命令调用如果包含参数，使用`:`隔开

显示相关基础命令

- `t`开头
- `b`结尾
- `exit`退出
- `⬆up`上一个
- `⬇down`下一个
- `PageUP`按键，上一页
- `PageDOWN`按键，下一页

Frida操作命令

- `hook:<target>`frida附加进程，`target`可以是应用名或者pid
    - 可以用在输入target的同时用逗号拼接初始化js文件，便于在hook的第一时间执行，例如`hook:Typora,/Users/soft98/ftool/code/typora.js`
- `list`列举当前附加的frida客户端
- `set:<client_id>`设置当前命令执行客户端，client_id可以通过`list`获取
- `exec:<cmd>`对当前frida客户端进行执行js代码，如果cmd为`exit`，frida客户端会退出
- `execf:<js_file>`对frida客户端进行执行指定文件中的js代码

![iShot_2023-11-30_11.29.10](assets/iShot_2023-11-30_11.29.10.gif)

## 0x03 已知问题

- 显示区域无法使用滚轮
- 显示内容过宽无法自动换行
