# safe-file-transfer-system
基于RSA+AES+SSL的文件安全传输系统

# 系统介绍

“SSS”文件安全传输系统是集AES、RSA、SSL三种算法于一身，为各种文件在网络环境安全传输保驾护航的文件安全传输系统。

服务端和客户端均使用了SSL证书验证（用openssl生成），socket传输文件，并自定义了传输包头。有GUI图形界面。同时使用了mysql数据库存储用户数据。

针对用户不同的情况，可自主选择是否需要SSL加密传输，上传文件时是否需要AES、RSA加密文件（AES对称密码加密文件，RSA非对称密码签名和验签）。

本系统涉及到简单的应用层协议设计，socket C/S 程序实现，SSL 安全传输协议，AES、RSA加解密算法，多线程技术，以及网络通信流量的嗅探与分析。

# 运行步骤

* 第一步，在msql数据库中创建名为“filetransfer“的数据库，新建表user，含有三个字段：id、username、password。表里可以先添加一条用户信息用于稍后登录，例如（id=1,username=123,password=123）；

* 第二步，解压源代码文件，修改server_ssl.py和server_no_ssl.py文件，将其中的mysql数据库名称和密码改成自己的；

* 第三步，安装相关依赖Python库：tkinter、pymysql、ssl、socket、rsa、pycrypto等（大多均为Python内置）；

* 第四步，启动程序，先启动服务器端代码：server_ssl.py和server_no_ssl.py，再启动客户端代码：main.py

# 程序说明

文件夹说明：

- cer -- 该文件夹存放了CA根证书及服务器、客户端证书（使用OpenSSL生成）

- - CA -- 根证书及秘钥
  - server -- 服务器秘钥、代签名证书及已签名证书
  - client -- 客户端秘钥、代签名证书及已签名证书

- ClientCache -- 该目录存放向服务器请求更新的下载列表数据

- ClientDownload -- 客户端下载路径

- ServerRec -- 服务器上传路径

文件说明：

\-   main.py 客户端启动文件

\-   client_login.py 客户端登录界面

\-   client_mian.py 客户端主界面

\-   view.py 客户端主界面视图

\-   client_socket_no_ssl.py 客户端不加密通信对象

\-   client_socket_ssl.py 客户端加密通信对象

\-   server_no_ssl.py 服务器不加密通信代码

\-   server_ssl.py 服务器加密不加密通信代码

\-   result.txt 用来记录服务器的下载列表

\-   Serverlog.txt 服务器日志

# 效果展示

### 1、登录界面

可选择是否使用SSL加密传输：

![login](https://edu-boker.oss-cn-beijing.aliyuncs.com/safe/1.png)

### 2、注册界面

![register](https://edu-boker.oss-cn-beijing.aliyuncs.com/safe/2.png)

### 3、下载界面

下载路径为项目文件夹下的 ClientDownload，下载采用多线程，点击确认后会后台下载，不影响当前页面操作。

![donload](https://edu-boker.oss-cn-beijing.aliyuncs.com/safe/3.png)

### 4、上传界面

上传同样采用多线程，不会影响当前界面的操作。上传的文件路径是项目目录下的ServerRec 文件夹。上传时可勾选是否使用AES、RSA加密：

![upload](https://edu-boker.oss-cn-beijing.aliyuncs.com/safe/4.png)

### 5、服务器日志

日志保存在项目目录下的 Serverlog.txt，记录了用户的登录、注册、上传、下载操作及具体的时间和操作的状态，如图：

![log](https://edu-boker.oss-cn-beijing.aliyuncs.com/safe/5.png)