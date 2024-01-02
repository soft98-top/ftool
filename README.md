# ftool
a simple frida tool for mac

工具目前只适用在macos上使用，目前存在或多或少的小问题，只作为调试使用，输出内容建议结合生成的log文件查看。

## 0x01 使用方法

`python/python3 ftool.py`

![image-20240102091412213](assets/image-20240102091412213.png)

## 0x02 命令

命令调用如果包含参数，使用`:`隔开

显示相关基础命令

- `t`开头
- `b`结尾
- `exit`退出，如果当前在exec命令空间下，会执行frida进程的退出
- `⬆up`上一个
- `⬇down`下一个
- `PageUP`按键，上一页
- `PageDOWN`按键，下一页
- `tab`按键，自动补齐，包含历史命令补齐，自动补齐需要在auto.json中配置

Frida操作命令

- `hook:<target>`frida附加进程，`target`可以是应用名或者pid
    - 可以用在输入target的同时用逗号拼接初始化js文件，便于在hook的第一时间执行，例如`hook:Typora,/Users/soft98/ftool/code/typora.js`
- `list`列举当前附加的frida客户端
- `set:<client_id>`设置当前命令执行客户端，client_id可以通过`list`获取
- `exec:<cmd>`对当前frida客户端进行执行js代码，如果cmd为`exit`，frida客户端会退出
- `execf:<js_file>`对frida客户端进行执行指定文件中的js代码
- `app:<target>`对app.json中配置的应用进行快速执行js代码，相当于`hook:<app>,<jsfile>`

![iShot_2024-01-02_09.31.52](assets/iShot_2024-01-02_09.31.52.gif)

## 0x03 已知问题

- ~~显示区域无法使用滚轮~~
  - 使用按键代替
- 显示内容过宽无法自动换行
- 显示内容无法复制
- frida进程切换不人性化
