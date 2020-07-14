from tkinter import *
from view import *  # 菜单栏对应的各个子页面
import threading

class MainPage(object):
    def __init__(self, master=None,client=None):
        self.root = master  # 定义内部变量root
        self.root.geometry('%dx%d' % (780, 400))  # 设置窗口大小
        self.client = client
        self.createPage()

    def createPage(self):
        self.downloadPage = DownloadFrame(self.root,self.client)  # 创建不同Frame
        self.uploadPage = UploadFrame(self.root,self.client)
        self.aboutPage = AboutFrame(self.root,self.client)
        self.downloadPage.pack()  # 默认显示数据录入界面
        menubar = Menu(self.root)
        menubar.add_command(label='文件列表', command=self.downloadData)
        menubar.add_command(label='上传文件', command=self.uploadData)
        menubar.add_command(label='关于', command=self.aboutDisp)
        self.root['menu'] = menubar  # 设置菜单栏
        self.root.resizable(0, 0)  # 阻止窗口变化

    def updateList(self):
        self.client.update()
        self.downloadPage.dealline()

    def downloadData(self):
        # 开启线程更新列表
        thread = threading.Thread(target=self.updateList,)
        thread.start()

        self.downloadPage.pack()
        self.uploadPage.pack_forget()
        self.aboutPage.pack_forget()

    def uploadData(self):
        self.downloadPage.pack_forget()
        self.uploadPage.pack()
        self.aboutPage.pack_forget()


    def aboutDisp(self):
        self.downloadPage.pack_forget()
        self.uploadPage.pack_forget()
        self.aboutPage.pack()