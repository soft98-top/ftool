import npyscreen
import curses
import logging
import frida
import threading
import re
import os
import time
import uuid
import json
import sys

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
HISTORY = []
LOCK1 = threading.Lock()

class FridaCLient():

    def __init__(self,target,repeat=False,auto=False,out=None):
        self.target = target
        self.repeat = repeat
        self.auto = auto
        self.out = out
    
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

class CustomForm(npyscreen.FormMutt):
    def create(self):
        self.max_height = self.lines - 6
        self.show_line_index = 0
        # 显示部分
        self.output = self.add(npyscreen.BoxTitle, name="Output",max_height=self.max_height)

        # 底部命令输入
        self.add(npyscreen.FixedText, value="Enter Command:", rely=-3, editable=False)
        self.command_input = self.add(npyscreen.Textfield, rely=-2)
        self.command_input.editable = True  # Ensure the input is editable
        
    def resize(self):
        # 在这里进行控件的重新布局或其他必要的调整
        # 在这里进行控件的重新布局或其他必要的调整
        self.max_height = self.lines - 6  # 自定义计算max_height，可根据需要调整
        self.output.max_height = self.max_height  # 设置 BoxTitle 控件的 max_height
        self.command_input.rely = self.lines - 2  # 重新定位输入框
        self.output_console("")

    def process_command(self, command_text:str):
        global CMD_CENTER,CURRENT
        command_parse = command_text.split(":")
        command = command_parse[0]
        basic_cmd = ['n','m','t','b']
        if command not in basic_cmd:
            self.output_console(f"Command entered: {command_text}")  # Logging command input
        if command in basic_cmd:
            if command_text == "n":
                if self.show_line_index > 0:
                    self.show_line_index = self.show_line_index - 1
            if command_text == "m":
                if self.show_line_index < len(HISTORY):
                    self.show_line_index = self.show_line_index + 1
            if command_text == "t":
                self.show_line_index = 0
            if command_text == "b":
                self.show_line_index = len(HISTORY) - int(self.output.max_height - 2)
            # if command == "clear":
            #     self.show_line_index = len(HISTORY)
            self.output_console("",force=True) 
        if command == "hook":
            args = command_parse[1].split(",")
            frida_client = FridaCLient(args[0],False,True,self)
            threading.Thread(target=frida_client.start).start()
        if command == "list":
            output_text = json.dumps(CMD_CENTER)
            self.output_console(output_text)
        if command == "set":
            client_id = command_parse[1]
            if CMD_CENTER.get(client_id,None) == None:
                self.output_console("frida client not found.")
            else:
                CURRENT = client_id
        if command == "exec":
            if CURRENT == "" or CMD_CENTER.get(CURRENT,None) == None:
                self.output_console("frida client not set.")
            else:
                client_id = CURRENT
                CMD_CENTER[client_id] = command_parse[1]
        if command == "execf":
            if CURRENT == "" or CMD_CENTER.get(CURRENT,None) == None:
                self.output_console("frida client not set.")
            else:
                client_id = CURRENT
                try:
                    cmd_code = open(command_parse[1],'r').read()
                    CMD_CENTER[client_id] = cmd_code
                except Exception as ex:
                    self.output_console(ex)
        if command == "exit":
            os._exit(0)
    
    def output_console(self, output_text, force=False):
        global HISTORY,LOCK1
        LOCK1.acquire()
        output_texts = output_text.split("\n")
        index = len(HISTORY) + 1
        for text in output_texts:
            if text.replace(" ","") != "" :
                out_str = f"[{index}] {text}"
                logger.info(out_str)
                HISTORY.append(out_str)
                index = index + 1
        if force == False:
            if len(HISTORY) >= int(self.output.max_height - 2):
                self.show_line_index = len(HISTORY) - int(self.output.max_height - 2)
        if self.show_line_index >= len(HISTORY):
            out_value = []
        else:
            out_value = HISTORY[self.show_line_index:]
        self.output.values = out_value
        self.output.display()  # Refresh the output
        LOCK1.release()

def main(stdscr):
    # 初始化 npyscreen
    app = npyscreen.NPSAppManaged()
    form = CustomForm()
    while True:
        # 监听键盘输入
        form.display()
        form.command_input.edit()
        command_text = form.command_input.value
        form.process_command(command_text)
        form.command_input.value = ''  # Clear input field after processing command
        form.command_input.update()  # Update the input field

def run_app():
    curses.wrapper(main)

if __name__ == "__main__":
    run_app()