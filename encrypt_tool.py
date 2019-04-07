# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
import os
import wx
# import rsa
import time
import uuid
import sys
import json
import traceback
import datetime
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import ConfigParser

LOG_PATH = ""
privatestr = \
"-----BEGIN RSA PRIVATE KEY-----\n\
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\n\
-----END RSA PRIVATE KEY-----\n"

padding = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
unpading = lambda s: s[0:-ord(s[-1])] if ord(s[-1]) <= 16 else s

def get_ver():
    cf = ConfigParser.ConfigParser()

    cf.read("info.conf")
    ver = cf.get("main", "ver")

    return ver


version = get_ver()

def Log(content):
    filename = os.path.join(LOG_PATH, 'run.log')
    stdout = sys.stdout
    reload(sys)
    sys.stdout = stdout
    try:
        time_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            content = time_now + " -- " + content.encode()
        except Exception:
            content = time_now + " -- " + content

        with open(filename, "a") as afile:
            afile.write(content + "\n")

        print content
        return True
    except:
        print ("error", "Log() exeption: %s" % traceback.format_exc())
        return False


def genkeypair():
    from Crypto.PublicKey import RSA
    key = RSA.generate(4096)
    pubkey = key.publickey().exportKey()
    privkey = key.exportKey()
    return (pubkey,privkey)


class MainWindow(wx.Frame):
    def __init__(self, parent, title):
        self.file_full_path = None
        self.dirname = None
        self.text_base_x = 120
        self.text_base_y = 50
        self.step = 40

        self.ctrl_base_x = 250
        self.ctrl_base_y = self.text_base_y
        self.ctrl_size = (324,21)
        self.ctrl_back_color = "RGB(154,205,50)"

        self.index = 0
        self.read_blk_size = 4 * 1024 * 1024
        self.head_size = 512

        mm = wx.DisplaySize()#获取屏幕的宽度，高度
        dlg_style = wx.SYSTEM_MENU | wx.MINIMIZE_BOX | wx.CAPTION | wx.CLOSE_BOX
        wx.Frame.__init__(self, parent,
                          title=title,
                          size=(200, 100),
                          pos=((mm[0]-660)/2, (mm[1]-360)/2),
                          style=dlg_style)
        #状态栏
        self.Bar = self.CreateStatusBar()
        #生成密钥
        self.ib = wx.IconBundle()
        self.ib = wx.IconBundle()
        self.ib.AddIconFromFile("bitbug_favicon.ico", wx.BITMAP_TYPE_ANY)
        self.SetIcons(self.ib)
        self.topPanel = wx.Panel(self)

        self.AddTextCtrl('加密密码：', "TexPassword")
        self.AddTextCtrl('密码确认：', "TexConfirm")
        self.AddTextCtrl('文件路径：', "WorkPath", bk_color="RGB(190,190,190)", style=wx.TE_READONLY)
        # self.AddTextCtrl('IDV桌面数：', "clientNum")
        # self.AddTextCtrl('VDI桌面数：', "vdiNum")
        # self.AddTextCtrl('序列号：', "TexSerialNumber",)
        # self.AddTextCtrl('有效期(天)：', "TexEffective")

        self.btnOK = wx.Button(self.topPanel, -1, '选择文件'.decode('UTF-8'),
                               (170, self.ctrl_base_y + self.step*self.index))
        self.btnGO = wx.Button(self.topPanel, -1, '加密'.decode('UTF-8'),
                               (300, self.ctrl_base_y + self.step*self.index))
        self.btnDeCrypt = wx.Button(self.topPanel, -1, '解密'.decode('UTF-8'),
                                    (400, self.ctrl_base_y + self.step*self.index))
        self.index += 1

        self.Bind(wx.EVT_BUTTON, self.btnOKClick, self.btnOK)
        self.Bind(wx.EVT_BUTTON, self.btnGOClick, self.btnGO)
        self.Bind(wx.EVT_BUTTON, self.btnDeCryptClick, self.btnDeCrypt)

        size_x = self.ctrl_base_x+self.ctrl_size[0] + self.text_base_x
        size_y = self.ctrl_base_y*2 + self.step*self.index
        self.SetSize(wx.Size(size_x, size_y))

        self.TexPassword.SetFocus()
        self.Show(True)

    def AddTextCtrl(self, static_text, ctrl_name, style=0, default_val="", bk_color=None):
        try:
            wx.StaticText(self.topPanel, -1, static_text.decode('UTF-8'),
                          (self.text_base_x, self.text_base_y + self.step*self.index))
            ctrl_obj = wx.TextCtrl(self.topPanel, -1, '', (self.ctrl_base_x, self.ctrl_base_y + self.step*self.index),
                                   style=style)
            ctrl_obj.SetSize(wx.Size(*self.ctrl_size))
            ctrl_obj.BackgroundColour = self.ctrl_back_color if bk_color is None else bk_color
            ctrl_obj.SetValue(default_val)
            setattr(self, ctrl_name, ctrl_obj)
            self.index += 1
        except:
            Log(traceback.format_exc())

        
    def btnOKClick(self,event):
        self.dirname = ''

        wildcard = u"pdf 文件 (*.pdf)|*.pdf|"\
                   "All file (*.*)|*.*"
        file_dlg = wx.FileDialog(self, "选择文件路径".decode('UTF-8'), self.dirname, "", wildcard,
                                 wx.OPEN)
        if file_dlg.ShowModal() == wx.ID_OK:
            self.file_full_path = file_dlg.GetPath()
            self.dirname = file_dlg.GetDirectory()
            global LOG_PATH

            LOG_PATH = self.dirname

            try:
                file_size = os.path.getsize(self.file_full_path)
            except:
                file_size = 0
            if not file_size:#判断序列号请求文件是否为空
                self.msg_box(u"文件无效，请重新选择")
                return

            self.SetCtrlVal()

    def SetCtrlVal(self, reg=None):
        if not reg:
            reg = dict()
        # file_full_path = os.path.join(self.dirname, )
        self.WorkPath.SetValue(self.file_full_path)
        self.TexPassword.SetValue("111111")
        self.TexConfirm.SetValue("111111")

    def ClearCtrlVal(self):
        self.SetCtrlVal(None)

    def save_data_to_excel(self, data):
        '''
        把数据存储到excel表格中
        :return:
        '''

    def msg_box(self, text, box_title=None):
        if not box_title:
            box_title = u"温馨提示"
        dl = wx.MessageDialog(self, text, box_title, wx.OK)
        dl.ShowModal()
        dl.Destroy()

    def btnGOClick(self, e):
        mes = self.TexPassword.GetValue()+self.TexConfirm.GetValue()+self.WorkPath.GetValue()
        if not mes:
            self.msg_box(u"请先选择要加密的文件")
            return

        password1 = self.TexPassword.GetValue()
        password2 = self.TexConfirm.GetValue()
        if not password1 or not password2 or len(password1) < 6 or len(password2) < 6:
            self.msg_box(u"密码长度不能小于6个字符")
            return

        if len(password1) > 32 or len(password2) > 32:
            self.msg_box(u"密码长度不能大于32个字符")
            return

        if password1 != password2:
            self.msg_box(u"两次输入密码不一致, 请检查后重新输入密码")
            return
        try:

            self.encrypt_file(self.file_full_path, self.file_full_path + ".encrypt.pdf", password=password1)

            # self.save_data_to_excel(data)
        except Exception as e:
            self.msg_box(str(e), "警告".decode('UTF-8'))

    def btnDeCryptClick(self, e):
        try:
            file_path = self.file_full_path
            if not file_path:
                self.msg_box("请先选择要解密的文件".decode('UTF-8'))
                return

            self.decrypt_file(self.file_full_path, self.file_full_path + '.decrypt.pdf')
        except:
            Log("btnDeCryptClick() exeption: %s" % (traceback.format_exc()))
            self.msg_box(u"处理文件出现异常: %s" % traceback.format_exc())
            return

    def LoadLicense(self, crypto):
        try:
            rsakey = RSA.importKey(privatestr)
            rsa_oaep = PKCS1_OAEP.new(rsakey)

            try:
                message = rsa_oaep.decrypt(crypto)
            except:
                Log("LoadLicense except: %s" % traceback.format_exc())
                self.msg_box(u"无效的加密文件")
                message = ""

            if not message:
                return ""

            try:
                retval = json.loads(message)
            except:
                Log("LoadLicense except: %s" % traceback.format_exc())
                self.msg_box(u"无效的加密文件")
                retval = {}
            if not retval:
                Log("message[%s] is not valid" % message)
                self.msg_box(u"无效的加密文件")

            Log("LoadLicense, license = %s" % retval)
            return retval
        except:
            Log("Check_license() exeption3: %s" % (traceback.format_exc()))
            self.msg_box(u"处理文件出现异常")
            return {}

    def encrypt_file(self, infile, outfile, password):
        exe_path = os.getcwd()
        Log("exe_path=%s" % exe_path)
        with open(os.path.join(exe_path, 'public.pem')) as publickfile:
            p = publickfile.read()

        file_size = os.path.getsize(infile)

        ver = get_ver()

        rsakey = RSA.importKey(p)
        rsa = PKCS1_OAEP.new(rsakey)

        lic_uuid = str(uuid.uuid1())

        data = dict(password=password,
                    CreatTime=time.strftime('%Y-%m-%d %X', time.localtime()),
                    UUID=lic_uuid,
                    Ver=ver,
                    file_size=file_size
                    )

        crpyto = rsa.encrypt(json.dumps(data))
        with open(outfile, 'wb') as outfp:
            outfp.write(crpyto)

        process_len = 0
        progress_max = 100
        dialog = wx.ProgressDialog(u"正在加密", u"处理进度", progress_max,
                style=wx.PD_CAN_ABORT | wx.PD_ELAPSED_TIME | wx.PD_REMAINING_TIME | wx.PD_AUTO_HIDE)
        keepGoing = True
        skiped = False
        # last_count = 0
        with open(outfile, 'ab') as outfp, open(infile, 'rb') as infp:
            ws = infp.read(self.read_blk_size)
            while ws:
                #
                if file_size - process_len <= self.read_blk_size:
                    ws = padding(ws)

                process_len += len(ws)
                ws = self.AES_cryption(ws, password)
                # ws = self.AES_cryption(ws)

                outfp.write(ws)
                count = (process_len * 100) / file_size
                keepGoing, skiped = dialog.Update(count)
                if not keepGoing:
                    Log("User canceled encrypting")
                    break
                ws = infp.read(self.read_blk_size)
        dialog.Destroy()
        if keepGoing:
            self.msg_box(u"加密完成")
        else:
            self.msg_box(u"操作取消")


        Log("encrypt success, uuid = (%s), version = (%s), message = (%s)"
            % (lic_uuid, version, json.dumps(data, indent=4)))

    def decrypt_file(self, infile, outfile):
        with open(infile, "rb") as fp:
            file_content = fp.read(self.head_size)

        if not file_content or len(file_content) < self.head_size:
            self.msg_box(u"无效的加密文件")
            return

        # 将收到的license内容转化成字典信息
        try:
            data = self.LoadLicense(file_content)
            if not data:
                Log("load license fail")
                return
        except:
            Log("ImportLicense except: %s" % traceback.format_exc())
            self.msg_box(u"处理文件出现异常")
            return

        # 输出解密内容
        file_size = data.get("file_size")
        if file_size is None:
            self.msg_box(u"无效的加密文件")
            return

        process_len = 0
        progress_max = 100
        dialog = wx.ProgressDialog(u"正在解密", u"处理进度", progress_max,
                                   style=wx.PD_CAN_ABORT | wx.PD_ELAPSED_TIME | wx.PD_REMAINING_TIME | wx.PD_AUTO_HIDE)
        keepGoing = True
        skiped = False

        with open(outfile, 'wb') as outfp, open(infile, 'rb') as infp:
            infp.read(self.head_size)
            ws = infp.read(self.read_blk_size)
            while ws:
                # file_size -= len(ws)
                # 最后一帧数据有可能小于read_blk_size, 也可能是read_blk_size+16长度
                left_len = file_size - process_len
                need_pading = (left_len <= self.read_blk_size or left_len == self.read_blk_size + 16)
                if need_pading:
                    tmp = infp.read()
                    ws += tmp

                process_len += len(ws)
                ws = self.AES_decryption(ws, data.get("password"))
                if need_pading:
                    # 尾帧要去补位
                    ws = unpading(ws)

                outfp.write(ws)

                count = (process_len * 100) / file_size
                keepGoing, skiped = dialog.Update(count)
                if not keepGoing:
                    Log("User canceled decrypting")
                    break
                ws = infp.read(self.read_blk_size)
        dialog.Destroy()
        if keepGoing:
            self.msg_box(u"解密完成")
        else:
            self.msg_box(u"操作取消")
    # AES加密
    @staticmethod
    def AES_cryption(plain, key=None):
        # AES加密需要输入字符串长度是16的整数倍, 所以要用PKCS7Padding补足成16的整数倍
        # plain = padding(plain)

        key = 'BgIAAACkAABSU0ExAAQAAAEAAQAfQFIF' if not key else key
        if len(key) < 32:
            key = padding(key)
        mode = AES.MODE_ECB
        encryptor = AES.new(key, mode)
        ciphertext = encryptor.encrypt(plain)
        return ciphertext

    #AES解密
    @staticmethod
    def AES_decryption(strcryption,
                       key=None,
                       mode=AES.MODE_ECB,
                       iv=None):
        # unpading = lambda s: s[0:-ord(s[-1])] if ord(s[-1]) <= 16 else s
        # padding = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
        key = 'BgIAAACkAABSU0ExAAQAAAEAAQAfQFIF' if not key else key
        if len(key) < 32:
            key = padding(key)
        iv = 'BgIAAACkAABSU0Ex' if not iv else iv
        if mode == AES.MODE_ECB:
            decryptor = AES.new(key, mode)
        else:
            decryptor = AES.new(key, mode, iv)

        plain = decryptor.decrypt(strcryption)

        return plain

    def onAction(self, event):
        raw_value = self.Hosts.GetValue().strip()
        # 只能输入整数
        if all(x in '0123456789.' for x in raw_value) and raw_value.find('.')<0:
            self.Hosts.SetValue(str(self.Hosts.GetValue()))
        else:
            self.msg_box(u"非法输入", u"警告")
            self.Hosts.ChangeValue("")
    def onActionEffective(self, event):
        raw_value = self.TexEffective.GetValue().strip()
        # 只能输入整数
        if all(x in '0123456789.' for x in raw_value) and raw_value.find('.')<0:
            self.TexEffective.SetValue(str(self.TexEffective.GetValue()))
        else:
            self.msg_box(u"非法输入", u"警告")
            self.TexEffective.ChangeValue("") 


if __name__ == "__main__":
    app = wx.App(False)

    title = u"文件加密解密器%s" % version
    frame = MainWindow(None, title)
    # frame.Centre()
    
    frame.style = wx.SYSTEM_MENU | wx.CAPTION | wx.CLOSE_BOX
    app.MainLoop()
