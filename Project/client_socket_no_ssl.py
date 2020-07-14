import socket
import time,os,struct,json,tkinter,threading,rsa

class client_no_ssl:
    def __init__(self):

        # 与服务端建立socket连接
        self.ssock = socket.create_connection(('127.0.0.1', 6666))

    def login(self,username,password):
        # 定义文件头信息，包含文件名和文件大小
        header = {
            'Command': 'Login',
            'fileName': '',
            'fileSize': '',
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            'user': username,
            'password': password,
        }
        header_hex = bytes(json.dumps(header).encode('utf-8'))
        fhead = struct.pack('1024s', header_hex)
        self.ssock.send(fhead)
        print('send over...')
        fileinfo_size = struct.calcsize('128s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            stat = header['stat']
            if stat == 'Success':
                fileSize = header['fileSize']
                filenewname = os.path.join(os.path.dirname(__file__)+'/ClientCache/', 'result.txt')
                print('file new name is %s, filesize is %s' % (filenewname, fileSize))
                recvd_size = 0  # 定义接收了的文件大小
                file = open(filenewname, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize:
                    if fileSize - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize - recvd_size)
                        recvd_size = fileSize
                    file.write(rdata)
                file.close()
                print('receive done')
                #self.ssock.close()
                return True

            else:
                return False

    def upload(self,filepath,useAES):
        if os.path.isfile(filepath):
            fileinfo_size = struct.calcsize('1024sl')  # 定义打包规则
            # 定义文件头信息，包含文件名和文件大小

            #在这里将要上传的文件AES加密和RSA签名生成一堆签名文件等
            print(useAES)
            size1=0;
            size2=0;
            size3=0;
            size4=0;
            size5=0;
            if useAES==1:  
                file=open(filepath,'rb')
                file_msg=file.read()
                aes_key_path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'AES_key')
                file_aes_key=open(aes_key_path,'rb')   # 打开AES秘钥文件
                aes_key=file_aes_key.read()
                from Crypto.Cipher import AES
                from Crypto import Random
                # iv用来记录AES随机生成的一个16字节初始向量
                iv = Random.new().read(AES.block_size)   # 使用Crypto中Random模块,读取16字节数据作为iv的值，AES分块大小固定为16字节
                print("开始对原文件进行AES加密......")
                file_encrypted_msg,fill_number=aes_encrypt(file_msg,aes_key,iv)
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_encrypted')
                file_encrypted=open(path,'wb')
                file_encrypted.write(file_encrypted_msg)
                file_encrypted.close()
                print("原文件AES加密完成！")
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'fill_number')
                file_fill_number=open(path,'w')
                file_fill_number.write(str(fill_number))
                file_fill_number.close()

                print("开始对原文件进行MD5摘要")
                md5_msg=md5_encrypt(file_msg)
                print("MD5摘要完成！")
                file.close()

                print("开始对MD5摘要签名")
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'Alice_private_key.pem')
                signature_msg=rsa_private_encrypt(md5_msg,path)
                print("MD5摘要签名完成！")
                print("对签名进行AES加密")
                signature_encrypted_msg,number=aes_encrypt(signature_msg,aes_key,iv) 
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_signature_encrypted')
                file_signature_encrypted=open(path,'wb')
                file_signature_encrypted.write(signature_encrypted_msg)
                file_signature_encrypted.close()
                print("签名AES加密完成！")

                print("开始对AES秘钥进行RSA加密")
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'Bob_public_key.pem')
                print("开始对AES秘钥进行RSA加密")
                aes_key_encrypted=rsa_public_encrypt(aes_key,path)
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'AES_key_encrypted')
                file_aes_key_encrypted=open(path,'wb')
                file_aes_key_encrypted.write(aes_key_encrypted)
                file_aes_key_encrypted.close()
                print("AES秘钥RSA加密完成！")
                print("开始对iv进行RSA加密")
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'Bob_public_key.pem')
                iv_encrypted=rsa_public_encrypt(iv,path)
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_iv_encrypted')
                file_iv_encrypted=open(path,'wb')
                file_iv_encrypted.write(iv_encrypted)
                file_iv_encrypted.close()
                print("对iv的RSA加密完成！")
                file_aes_key.close()

                print("加密过程结束！")
                print("你需要发送给接收者的文件有：")
                print("1.已加密文件：file_encrypted")
                print("2.加密后的AES秘钥文件：AES_key_encrypted")
                print("3.AES加密后的初始化向量文件：file_iv_encrypted")
                print("4.加密后的签名文件：file_signature_encrypted")
                print("5.填充位数文件：fill_number")
                print("\n最后请删除程序所在路径下加入和生成的文件，谢谢！")

                path1=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_encrypted')
                path2=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'AES_key_encrypted')
                path3=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_iv_encrypted')
                path4=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_signature_encrypted')
                path5=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'fill_number')
                size1=os.stat(path1).st_size
                size2=os.stat(path2).st_size
                size3=os.stat(path3).st_size
                size4=os.stat(path4).st_size
                size5=os.stat(path5).st_size
            header = {
                'Command': 'Upload',
                'fileName': os.path.basename(filepath),
                'fileSize': os.stat(filepath).st_size,
                'fileSize1': size1,
                'fileSize2': size2,
                'fileSize3': size3,
                'fileSize4': size4,
                'fileSize5': size5,
                'useAES': useAES,
                'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                'user': self.username,
                'password': self.password,
                'downloadFilename': '',
                'cookie': ''
            }
            header_hex = bytes(json.dumps(header).encode('utf-8'))
            fhead = struct.pack('1024s', header_hex)
            self.ssock.send(fhead)
            

            if useAES==1:
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_encrypted')
                f1=open(path,'rb')
                while True:
                    filedata = f1.read(1024)
                    if not filedata:
                        break
                    self.ssock.send(filedata)
                f1.close()
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'AES_key_encrypted')
                f2=open(path,'rb')
                while True:
                    filedata = f2.read(1024)
                    if not filedata:
                        break
                    self.ssock.send(filedata)
                f2.close()
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_iv_encrypted')
                f3=open(path,'rb')
                while True:
                    filedata = f3.read(1024)
                    if not filedata:
                        break
                    self.ssock.send(filedata)
                f3.close()
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_signature_encrypted')
                f4=open(path,'rb')
                while True:
                    filedata = f4.read(1024)
                    if not filedata:
                        break
                    self.ssock.send(filedata)
                f4.close()
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'fill_number')
                f5=open(path,'rb')
                while True:
                    filedata = f5.read(1024)
                    if not filedata:
                        break
                    self.ssock.send(filedata)
                f5.close()
            else:
                fo = open(filepath, 'rb')
                while True:
                    filedata = fo.read(1024)
                    if not filedata:
                        break
                    self.ssock.send(filedata)
                fo.close()

            #在这里将一堆文件传过去
            #删除签名文件等

            print('send over...')
            tkinter.messagebox.showinfo('提示！', message='上传成功')
            #self.ssock.close()
        else:
            print('ERROR FILE')

    def download(self, filename):
        # 定义文件头信息，包含文件名和文件大小
        header = {
            'Command': 'Download',
            'fileName': filename,
            'fileSize': '',
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            'user': self.username,
            'password': self.password,
        }
        header_hex = bytes(json.dumps(header).encode('utf-8'))
        fhead = struct.pack('1024s', header_hex)
        self.ssock.send(fhead)

        fileinfo_size = struct.calcsize('1024s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            header_json = str(struct.unpack('1024s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            stat = header['stat']
            if stat == 'Success':
                fileSize = header['fileSize']
                fileSize1 = header['fileSize1']
                fileSize2 = header['fileSize2']
                fileSize3 = header['fileSize3']
                fileSize4 = header['fileSize4']
                fileSize5 = header['fileSize5']
                
                recvd_size = 0  # 定义接收了的文件大小
                path1=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_encrypted')
                file1 = open(path1, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize1:
                    if fileSize1 - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize1 - recvd_size)
                        recvd_size = fileSize1
                    file1.write(rdata)
                file1.close()

                recvd_size = 0  # 定义接收了的文件大小
                path2=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'AES_key_encrypted')
                file2 = open(path2, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize2:
                    if fileSize2 - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize2 - recvd_size)
                        recvd_size = fileSize2
                    file2.write(rdata)
                file2.close()

                recvd_size = 0  # 定义接收了的文件大小
                path3=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_iv_encrypted')
                file3 = open(path3, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize3:
                    if fileSize3 - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize3 - recvd_size)
                        recvd_size = fileSize3
                    file3.write(rdata)
                file3.close()

                recvd_size = 0  # 定义接收了的文件大小
                path4=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'file_signature_encrypted')
                file4 = open(path4, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize4:
                    if fileSize4 - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize4 - recvd_size)
                        recvd_size = fileSize4
                    file4.write(rdata)
                file4.close()

                recvd_size = 0  # 定义接收了的文件大小
                path5=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'fill_number')
                file5 = open(path5, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize5:
                    if fileSize5 - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize5 - recvd_size)
                        recvd_size = fileSize5
                    file5.write(rdata)
                file5.close()

                file_aes_key_encrypted=open(path2,'rb')
                aes_key_encrypted=file_aes_key_encrypted.read()
                file_iv_encrypted=open(path3,'rb')
                iv_encrypted=file_iv_encrypted.read()

                print("开始解密AES秘钥")
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'Alice_private_key.pem')
                aes_key=rsa_private_decrypt(aes_key_encrypted, path)
                print("AES秘钥解密完成！")
                print("开始解密AES初始化向量")
                iv=rsa_private_decrypt(iv_encrypted,path)
                print("AES初始化向量解密完成！")
                file_encrypted=open(path1,'rb') 
                file_encrypted_msg=file_encrypted.read()

                file_fill_number=open(path5,'rb')
                fill_number=file_fill_number.read()
                print("开始对加密文件进行AES解密")
                file_msg=aes_decrypt(file_encrypted_msg,aes_key,iv)
                file_msg=file_msg[0:len(file_msg)-int(fill_number)]
                print("加密文件AES解密完成！")
                file_fill_number.close()
                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', filename)
                file_decrypted=open(path,'wb')
                file_decrypted.write(file_msg)
                md5_file_msg=md5_encrypt(file_msg)
                file_decrypted.close()
                file_encrypted.close()

                file_signature_encrypted=open(path4,'rb')
                signature_encrypted=file_signature_encrypted.read()
                print("加密签名文件AES解密")
                file_signature=aes_decrypt(signature_encrypted,aes_key,iv)
                print("加密签名文件AES解密完成！")
                file_signature_encrypted.close()
                file_aes_key_encrypted.close()         # AES解密完成，关闭相关文件
                file_iv_encrypted.close()

                path=os.path.join(os.path.dirname(__file__)+'/ClientDownload/', 'Bob_public_key.pem')
                print("开始签名文件RSA解密")
                with open(path,'r') as f:
                    pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())
                rsa.verify(md5_file_msg.encode(), file_signature, pubkey)
                print("MD5值校验成功！")
                print("解密程序运行完毕，请提取解密文件，并删除此程序所在路径下导入及生成的文件，谢谢！")

                #在这里接受那些和加密有关的签名文件等
                #解密和验签
                #删除和接收到的和加密有关的签名文件等

                print('receive done')
                # self.ssock.close()
                tkinter.messagebox.showinfo('提示！',message='下载成功：' + filename)
                return True

            else:
                return False

    def update(self):
        # 定义文件头信息，包含文件名和文件大小
        header = {
            'Command': 'Update',
            'fileName': '',
            'fileSize': '',
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            'user': self.username,
            'password': self.password
        }
        header_hex = bytes(json.dumps(header).encode('utf-8'))
        fhead = struct.pack('1024s', header_hex)
        self.ssock.send(fhead)
        print('ask for updating...')
        fileinfo_size = struct.calcsize('128s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            stat = header['stat']
            if stat == 'Success':
                fileSize = header['fileSize']
                filenewname = os.path.join(os.path.dirname(__file__)+'/ClientCache/', 'result.txt')
                print('file new name is %s, filesize is %s' % (filenewname, fileSize))
                recvd_size = 0  # 定义接收了的文件大小
                file = open(filenewname, 'wb')
                print('start receiving...')
                while not recvd_size == fileSize:
                    if fileSize - recvd_size > 1024:
                        rdata = self.ssock.recv(1024)
                        recvd_size += len(rdata)
                    else:
                        rdata = self.ssock.recv(fileSize - recvd_size)
                        recvd_size = fileSize
                    file.write(rdata)
                file.close()
                print('receive done')
                # self.ssock.close()

    def register(self,username,password):
        # 定义文件头信息，包含文件名和文件大小
        header = {
            'Command': 'Register',
            'fileName': '',
            'fileSize': '',
            'time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            'user': username,
            'password': password,
        }
        header_hex = bytes(json.dumps(header).encode('utf-8'))
        fhead = struct.pack('1024s', header_hex)
        self.ssock.send(fhead)
        print('Under registration...')
        fileinfo_size = struct.calcsize('128s')
        buf = self.ssock.recv(fileinfo_size)
        if buf:  # 如果不加这个if，第一个文件传输完成后会自动走到下一句
            header_json = str(struct.unpack('128s', buf)[0], encoding='utf-8').strip('\00')
            print(header_json)
            header = json.loads(header_json)
            stat = header['stat']
            if stat == 'Success':
                return True

            else:
                return False
    

def aes_encrypt(aes_file, key,iv):  # aes_file 文件，key 16-bytes 对称秘钥
    from Crypto.Cipher import AES
    from Crypto import Random
    cipher = AES.new(key, AES.MODE_OFB,iv)   # 生成了加密时需要的实际密码,这里采用OFB模式
    # if fs is a multiple of 16
    x = len(aes_file) % 16
    print("要加密文件的长度是： %d"%len(aes_file))
    print("需要填充的数据长度 : %d"%((16- x)%16))
    if x != 0:
        aes_file_pad = aes_file + b'0'*(16 - x) # It should be 16-x
    else:
        aes_file_pad=aes_file
    msg = cipher.encrypt(aes_file_pad)
    return msg,(16- x)%16

# AES解密
def aes_decrypt(aes_file, key,iv):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_OFB,iv)   # 生成了解密时需要的实际密码,这里采用OFB模式
    msg=cipher.decrypt(aes_file)
    return msg

# 计算MD5值
def md5_encrypt(md5_file):
    from Crypto.Hash import MD5
    msg = MD5.new()
    msg.update(md5_file)
    return msg.hexdigest()

# RSA私钥加密
def rsa_private_encrypt(msg,file_rsa_private_key_name):
    # from M2Crypto import RSA    # 用M2Crypto下的RSA模块
    # rsa_private_key=RSA.load_key(file_rsa_private_key_name)
    # msg_encrypted=rsa_private_key.private_encrypt(msg,RSA.pkcs1_padding)
    # return msg_encrypted
    with open (file_rsa_private_key_name,'r') as f:
        rsa_private_key=rsa.PrivateKey.load_pkcs1(f.read().encode())
    msg_encrypted=rsa.sign(msg.encode(), rsa_private_key, 'SHA-1')
    return msg_encrypted

# RSA公钥加密
def rsa_public_encrypt(msg,file_rsa_public_name):
    # from M2Crypto import RSA    # 用M2Crypto下的RSA模块
    # rsa_public_key=RSA.load_pub_key(file_rsa_public_name)
    # msg_encrypted=rsa_public_key.public_encrypt(msg,RSA.pkcs1_padding)
    # return msg_encrypted
    with open(file_rsa_public_name,'r') as f:
        rsa_public_key=rsa.PublicKey.load_pkcs1(f.read().encode())
    msg_encrypted=rsa.encrypt(msg, rsa_public_key)
    return msg_encrypted
#  RSA私钥解密
def rsa_private_decrypt(msg,file_rsa_private_key_name):
    # from M2Crypto import RSA    # 用M2Crypto下的RSA模块
    # rsa_private_key=RSA.load_key(file_rsa_private_key_name)
    # msg_decrypted=rsa_private_key.private_decrypt(msg,RSA.pkcs1_padding)
    # return msg_decrypted
    with open(file_rsa_private_key_name,'r') as f:
        rsa_private_key=rsa.PrivateKey.load_pkcs1(f.read().encode())
    msg_decrypted=rsa.decrypt(msg, rsa_private_key)
    return msg_decrypted

#  RSA公钥解密
def rsa_public_decrypt(msg,file_rsa_public_name):
    # from M2Crypto import RSA    # 用M2Crypto下的RSA模块
    # rsa_public_key=RSA.load_pub_key(file_rsa_public_name)
    # msg_decrypted=rsa_public_key.public_decrypt(msg,RSA.pkcs1_padding)
    # return msg_decrypted
    with open(file_rsa_public_name,'r') as f:
        rsa_public_key=rsa.PublicKey.load_pkcs1(f.read().encode())
    msg_decrypted=rsa.decrypt(msg, rsa_public_key)
    return msg_decrypted
        


if __name__ == "__main__":
    client = client_no_ssl()
    filepath = 'D:\重要资料\项目&作业\项目\网络攻防实验\文件安全传输系统\cer\server\server.crt'
    client.login('lindada','lindada')
    client.upload(filepath)