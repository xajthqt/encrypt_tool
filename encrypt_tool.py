# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
import os
import wx
import rsa
import time
import uuid
import sys
import json
import traceback
import datetime
from Crypto.Cipher import AES
import ConfigParser

LOG_PATH = ""
privatestr = \
"-----BEGIN RSA PRIVATE KEY-----\n\
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\n\
MbpOy3IePyTujw==\n\
-----END RSA PRIVATE KEY-----\n"

padding = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
unpading = lambda s: s[0:-ord(s[-1])] if ord(s[-1]) <= 16 else s

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


def get_ver():
    cf = ConfigParser.ConfigParser()

    cf.read("info.conf")
    ver = cf.get("main", "ver")

    return ver

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
        #(pubkey, privkey) = rsa.newkeys(1024) 

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

            # output = self.AES_cryption(fc)

            # info = self.AES_decryption(fc)
            # if info.find(",,,") >= 0:
            #     reg_info = info.split(",,,")
            #     reg = dict()
            #     reg["sys_id"] = reg_info[0]
            #     reg["contract"] = reg_info[1]
            #     reg["company"] = reg_info[2]
            #     reg["host_num"] = reg_info[3]
            # else:
            #     try:
            #         reg = json.loads(info)
            #     except:
            #         print traceback.format_exc()
            #
            # file_dlg.Destroy()
            self.SetCtrlVal()

    def SetCtrlVal(self, reg=None):
        if not reg:
            reg = dict()
        # file_full_path = os.path.join(self.dirname, )
        self.WorkPath.SetValue(self.file_full_path)
        self.TexPassword.SetValue("111111")
        self.TexConfirm.SetValue("111111")
        # self.TexContract.SetValue(reg.get("contract", ""))
        # self.TexConfirm.SetValue(reg.get("company", ""))
        # self.Hosts.SetValue(reg.get("host_num", ""))
        # self.clientNum.SetValue(reg.get("host_num", ""))
        # self.vdiNum.SetValue(reg.get("vdi_num", "") if reg.get("vdi_num", "") else reg.get("host_num", ""))
        # self.TexEffective.SetValue(reg.get("effect", ""))

    def ClearCtrlVal(self):
        self.SetCtrlVal(None)

    # def __get_excel_path(self):
    #     fn = "license交付记录.xlsx".decode("UTF-8")
    #     default_path = os.path.join(self.dirname, fn)
    #     try:
    #         lic_dir = self.dirname.strip("\\")
    #         par_path, dirname = os.path.split(lic_dir)
    #         while dirname:
    #             if dirname == "license交付记录":
    #                 excel_path = os.path.join(par_path, dirname, fn)
    #                 if os.path.exists(excel_path):
    #                     return excel_path
    #                 else:
    #                     return default_path
    #
    #
    #     except:
    #         Log("__get_excel_path except: %s" % traceback.format_exc())
    #         return default_path

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

    def LoadLicense(self, crypto):
        try:
            privkey = rsa.PrivateKey.load_pkcs1(privatestr)
            # message = ""

            try:
                message = rsa.decrypt(crypto, privkey)
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

    def encrypt_file(self, infile, outfile, password):
        exe_path = os.getcwd()
        Log("exe_path=%s" % exe_path)
        with open(os.path.join(exe_path, 'public.pem')) as publickfile:
            p = publickfile.read()

        file_size = os.path.getsize(infile)

        ver = get_ver()
        pubkey = rsa.PublicKey.load_pkcs1(p)
        lic_uuid = str(uuid.uuid1())

        data = dict(password=password,
                    CreatTime=time.strftime('%Y-%m-%d %X', time.localtime()),
                    UUID=lic_uuid,
                    Ver=ver,
                    file_size=file_size
                    )

        crpyto = rsa.encrypt(json.dumps(data), pubkey)
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
    version = get_ver()
    title = u"文件加密解密器%s" % version
    frame = MainWindow(None, title)
    # frame.Centre()
    
    frame.style = wx.SYSTEM_MENU | wx.CAPTION | wx.CLOSE_BOX
    app.MainLoop()
