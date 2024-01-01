import urwid
import os
import logging
import threading
import re
import time
import uuid
import json
import sys
import frida
# import difflib

# Configuring logger to write to a file
logging.basicConfig(level=logging.INFO, filename=f'ftool-{time.time()}.log', filemode='w',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 获取程序所在目录
BASE_PATH = os.path.dirname(sys.executable) + '/'
## 判断如果是py文件运行，则获取py文件所在目录
if os.path.basename(sys.executable) in ['python.exe', 'python3.exe', 'python', 'python3']:
    BASE_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'
JSPATH = BASE_PATH + "code/all-in-one.js"
CMD_CENTER = {}
CURRENT = ""
TOTAL_HISTORY = urwid.SimpleListWalker([])
HISTORY = urwid.SimpleListWalker([])
OUTPUT = urwid.SimpleListWalker([])
LOCK1 = threading.Lock()
CURRENT_CMD = "$"
AUTO_JSON = BASE_PATH + "auto.json"
AUTO_DATA = {}

class FridaCLient():

    def __init__(self,target,repeat=False,auto=False,out=None,init_script=None):
        self.target = target
        self.repeat = repeat
        self.auto = auto
        self.out = out
        self.init_script = init_script
    
    def open_app(self):
        if type(self.target) == str:
            target = self.target.replace(" ","\\ ")
            os.system('open -a {} -g'.format(target))
        
    def on_message(self,message,data):
        out_data = ""
        try:
            if message['type'] == 'send':
                out_data = message.get('payload',None)
                if out_data == None:
                    return
            elif message['type'] == 'error':
                out_data = message['stack']
            else:
                out_data = message
        except:
            out_data = message
        out_data = str(out_data)
        self.out.output_console(out_data)
    
    def start(self):
        global CMD_CENTER,CURRENT
        target = None
        try:
            target = int(self.target)
        except:
            target = self.target
        while True:
            try:
                session = frida.attach(target)
                break
            except Exception as ex:
                error = str(ex)
                self.out.output_console(error)
                if error.startswith('ambiguous name; it matches:'):
                    pattern = re.compile(r'pid: \d+')
                    choices = pattern.findall(error)
                    self.out.output_console(choices)
                    return
                    # for pid in choices:
                    #     thread = threading.Thread(target=hook,args=(pid.replace('pid: ',''),jsf,*args))
                    #     thread.start()
                    # return
                if self.auto:
                    self.open_app()
                time.sleep(0.2)
        script_data = open(JSPATH,'r',encoding='utf-8').read()
        script = session.create_script(script_data)
        script.on('message',self.on_message)
        script.load()
        script_uuid = str(uuid.uuid1())
        self.out.output_console(f'Hook进程成功({str(target)})({script_uuid})')
        if self.init_script != None:
            init_script_data = open(self.init_script,'r',encoding='utf-8').read()
            script.post(init_script_data)
        CMD_CENTER[script_uuid] = ""
        CURRENT = script_uuid
        while True and session.is_detached == False:
            cmd = CMD_CENTER[script_uuid]
            CMD_CENTER[script_uuid] = ""
            if cmd != "":
                if cmd == "exit":
                    session.detach()
                else:
                    script.post(cmd)
            time.sleep(0.2)
        CMD_CENTER.pop(script_uuid)
        self.out.output_console(f"{script_uuid} done.")

class FToolUrwid:
    def __init__(self):
        global OUTPUT
        self.output_widget = OUTPUT
        self.output_listbox = urwid.ListBox(self.output_widget)
        self.out_index = 0
        # 取当前屏幕的高度
        self.max_out = os.get_terminal_size().lines - 3
        self.scrollable_output = urwid.LineBox(self.output_listbox, title="Output", title_align="left")
        self.input_edit = urwid.Edit(caption="Command: ")
        self.frame = urwid.Frame(body=self.scrollable_output, footer=self.input_edit)
        self.loop = urwid.MainLoop(self.frame, unhandled_input=self.handle_input)

    def handle_input(self, key):
        global HISTORY
        self.max_out = os.get_terminal_size().lines - 3
        # self.output_console(f"Input: {key}")  # Logging command input
        if key == 'enter':
            command = self.input_edit.edit_text.strip()
            if command == "":
                # 输入框聚焦
                self.frame.focus_position = 'footer'
                return
            self.execute_command(command)
            self.input_edit.edit_text = ""
        # 如果是滚轮向上滚动或鼠标滚轮向上滚动
        elif key == 'up':
            out_index = self.out_index
            if out_index > 0:
                self.out_index = out_index - 1
                self.output_widget[:] = HISTORY[self.out_index:]
        # 如果是滚轮向下滚动或鼠标滚轮向下滚动
        elif key == 'down':
            out_index = self.out_index
            if out_index < len(HISTORY) - self.max_out:
                self.out_index = out_index + 1
                self.output_widget[:] = HISTORY[self.out_index:]
        # 如果是Page Up
        elif key == 'page up':
            out_index = self.out_index
            self.out_index = out_index - self.max_out
            if self.out_index < 0:
                self.out_index = 0
            self.output_widget[:] = HISTORY[self.out_index:]
        # 如果是Page Down
        elif key == 'page down':
            out_index = self.out_index
            if out_index < len(HISTORY) - self.max_out:
                self.out_index = out_index + self.max_out
                if self.out_index > len(HISTORY) - self.max_out:
                    self.out_index = len(HISTORY) - self.max_out
                self.output_widget[:] = HISTORY[self.out_index:]
        elif key == 'tab':
            input = self.input_edit.edit_text.strip()
            self.autocomplete_command(input)
    
    def autocomplete_command(self, input):
        global CURRENT_CMD
        # if CURRENT_CMD == "":
        #     return
        options = AUTO_DATA.get(CURRENT_CMD,[])
        if len(options) == 0:
            return
        # matches = difflib.get_close_matches(input, options, cutoff=0.3, n=len(options))
        matches = [cmd for cmd in options if cmd.startswith(input)]
        if len(matches) == 1:
            self.input_edit.edit_text = matches[0]
            # 光标移动到最后
            self.input_edit.set_edit_pos(len(matches[0]))
        elif len(matches) > 1:
            common_prefix = os.path.commonprefix(matches)
            if common_prefix:
                if common_prefix == input:
                    self.output_console("\n".join(matches))
                    return
                self.input_edit.edit_text = common_prefix
                # 光标移动到最后
                self.input_edit.set_edit_pos(len(common_prefix))
    
    def command_add_history(self, command):
        global CURRENT_CMD
        # if CURRENT_CMD == "":
        #     return
        options = AUTO_DATA.get(CURRENT_CMD,[])
        if command not in options:
            options.append(command)
            AUTO_DATA[CURRENT_CMD] = options

    def execute_command(self, command_text):
        global CMD_CENTER,CURRENT,HISTORY,BASE_PATH
        command_parse = command_text.split(":")
        command = command_parse[0]
        command_args = ""
        if len(command_parse) > 1:
            command_args = command_parse[1]
        basic_cmd = ['t','b','clear']
        special_cmd = ['hook','set','exec','execf','app']
        self.command_add_history(command_text)
        if command not in basic_cmd:
            self.output_console(f"Command: {command_text}")  # Logging command input
        if command in basic_cmd:
            out_index = self.out_index
            if command_text == "t":
                self.out_index = 0
            if command_text == "b":
                self.out_index = len(HISTORY) - self.max_out
            if command == "clear":
                self.out_index = 0
                HISTORY.clear()
            if out_index != self.out_index or command == "clear":
                self.output_widget[:] = HISTORY[self.out_index:]
        elif command == "list":
            output_text = json.dumps(CMD_CENTER)
            self.output_console(output_text)
        elif command == "exit":
            os._exit(0)
        elif command in special_cmd and command_args == "":
            self.change_cmd(command)
            return
        else:
            if command_args == "":
                command = CURRENT_CMD
                command_args = command_text
            if command == "hook":
                args = command_args.split(",")
                app_name = args[0]
                init_script = None
                if len(args) > 1:
                    init_script = args[1]
                frida_client = FridaCLient(app_name,False,True,self,init_script)
                threading.Thread(target=frida_client.start).start()
            elif command == "set":
                client_id = command_args
                if CMD_CENTER.get(client_id,None) == None:
                    self.output_console("frida client not found.")
                else:
                    CURRENT = client_id
            elif command == "exec":
                if CURRENT == "" or CMD_CENTER.get(CURRENT,None) == None:
                    self.output_console("frida client not set.")
                else:
                    client_id = CURRENT
                    CMD_CENTER[client_id] = command_args
            elif command == "execf":
                if CURRENT == "" or CMD_CENTER.get(CURRENT,None) == None:
                    self.output_console("frida client not set.")
                else:
                    client_id = CURRENT
                    try:
                        cmd_code = open(command_args,'r').read()
                        CMD_CENTER[client_id] = cmd_code
                    except Exception as ex:
                        self.output_console(str(ex))
            elif command == "app":
                app_data = json.loads(open('app.json','r').read())
                app_key = command_args.lower();
                app_info = app_data.get(command_args,{})
                if app_info == {}:
                    return
                else:
                    app_name = app_info["app"]
                    init_script = app_info["jsf"].replace("@BASE/",BASE_PATH)
                    frida_client = FridaCLient(app_name,False,True,self,init_script)
                    threading.Thread(target=frida_client.start).start()
        

    def output_console(self, output_text):
        global HISTORY,TOTAL_HISTORY,LOCK1
        LOCK1.acquire()
        output_texts = output_text.split("\n")
        for text in output_texts:
            if text.strip() != "":
                HISTORY.append(urwid.Text(f'[{len(HISTORY) + 1}] {text}'))
                log_str = f'[{len(TOTAL_HISTORY) + 1}] {text}'
                TOTAL_HISTORY.append(urwid.Text(log_str))
                logger.info(log_str)
        if len(HISTORY) > self.max_out:
            self.out_index = len(HISTORY) - self.max_out
        self.output_widget[:] = HISTORY[self.out_index:]
        LOCK1.release()
        # 刷新显示
        self.loop.draw_screen()
    
    def change_cmd(self, cmd:str):
        global CURRENT_CMD
        CURRENT_CMD = cmd
        caption = "Command: "
        if cmd != "":
            caption = f"Command({cmd}): "
        # 修改caption
        self.input_edit.set_caption(caption)

    def run(self):
        self.loop.run()

if __name__ == '__main__':
    ftool_urwid = FToolUrwid()
    try:
        AUTO_DATA = json.loads(open(AUTO_JSON,'r').read())
    except:
        AUTO_DATA = {}
    ftool_urwid.run()