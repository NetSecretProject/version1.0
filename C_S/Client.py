import socket  # Import socket module
import time
import traceback
import select
from threading import Thread
from RSA import RSAdecrypt, RSAencrypt, newKey
from DES import DESdecrypt, DESencrypt
import hashlib
from tkinter import *
from tkinter import scrolledtext
from tkinter.ttk import *

hostIP = "172.20.10.10"
# (n, e, d) = newKey(10 ** 100, 10 ** 101, 50)
# print("generating client key...")
# fo = open("KpC.txt", "w")
# fo.write(str(n))
# fo.write('\n')
# fo.write(str(e))   # write public key to the keyfile
# fo.write('\n')
# fo.write(str(d))
# fo.close()


def generateKctgs(_Kctgs):
    Kctgstext = _Kctgs[1:len(_Kctgs) - 1].split(", ")
    Kctgslist = []
    for Hex in Kctgstext:
        Kctgslist.append(int(Hex, 16))
    return Kctgslist


def generateKcv(_Kcv):
    Kcvtext = _Kcv[1:len(_Kcv) - 1].split(", ")
    Kcvlist = []
    for Hex in Kcvtext:
        Kcvlist.append(int(Hex, 16))
    return Kcvlist

def parseAScipher(AS_cipher):
    ciphertext = AS_cipher[1:len(AS_cipher) - 1].split(", ")
    cipherlist = []
    for Num in ciphertext:
        cipherlist.append(int(Num))
    KctgsList = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59]
    AS2C = DESdecrypt(KctgsList, cipherlist)
    print(AS2C)
    AS2CList = AS2C.split("  ")
    kctgs = AS2CList[0]
    idtgs = AS2CList[1]
    ts2 = AS2CList[2]
    lifetime = AS2CList[3]
    tickettgs = AS2CList[4]
    return kctgs, idtgs, ts2, lifetime, tickettgs


def ParseTGS2C(Kctgs, TGS2C_cipher):
    TGS2Ctext = TGS2C_cipher[1:len(TGS2C_cipher) - 1].split(", ")
    TGS2Clist = []
    for num in TGS2Ctext:
        TGS2Clist.append(int(num))
    TGS2C = DESdecrypt(Kctgs, TGS2Clist).split("  ")
    kcv = TGS2C[0]
    idv = TGS2C[1]
    ts4 = TGS2C[2]
    ticketv = TGS2C[3]
    return kcv, idv, ts4, ticketv


def VerifyASSignature(cipher, Signature):
    Sigtext = Signature[1:len(Signature) - 1].split(", ")
    Signature = []
    for num in Sigtext:
        Signature.append(int(num))
    foAS = open("KpAS.txt", "r+")  # 可以简化为一个函数
    KAS = foAS.readlines()
    ASn = int(KAS[0])
    ASe = int(KAS[1])
    Verify = RSAdecrypt(Signature, ASn, ASe, 8)
    Hash = hashlib.md5(cipher.encode()).hexdigest()
    if Verify == Hash:
        print("Signature verify successfully")
        return True
    else:
        print("Signature doesn't Match...")
        return False


def VerifyTGSSignature(cipher, Signature):
    Sigtext = Signature[1:len(Signature) - 1].split(", ")
    Signature = []
    for num in Sigtext:
        Signature.append(int(num))
    foTGS = open("KpTGS.txt", "r+")
    KTGS = foTGS.readlines()
    TGSn = int(KTGS[0])
    TGSe = int(KTGS[1])
    Verify = RSAdecrypt(Signature, TGSn, TGSe, 8)
    Hash = hashlib.md5(cipher.encode()).hexdigest()
    if Verify == Hash:
        print("Signature verify successfully")
        return True
    else:
        print("Signature doesn't Match...")
        return False


def VerifySSignature(SS2C, ss_Signature):
    Sigtext = ss_Signature[1:len(ss_Signature) - 1].split(", ")
    Signature = []
    for num in Sigtext:
        Signature.append(int(num))
    foSS = open("KSS.txt", "r+")
    KSS = foSS.readlines()
    SSn = int(KSS[0])
    SSe = int(KSS[1])
    Verify = RSAdecrypt(Signature, SSn, SSe, 8)
    Hash = hashlib.md5(SS2C.encode()).hexdigest()
    if Verify == Hash:
        print("Signature verify successfully")
        return True
    else:
        print("Signature doesn't Match...")
        return False


def parseSScipher(kcv, ss2c):
    ss2ctext = ss2c[1:len(ss2c) - 1].split(", ")
    ss2c = []
    for num in ss2ctext:
        ss2c.append(int(num))
    ss2c = DESdecrypt(kcv, ss2c)
    return int(ss2c)


def inputmessage(s):
    message1 = input()
    print("<YOU>"+message1)
    s.send(message1.encode())


# ============== Module for python GUI====================#
window = Tk()
window.title("Welcome to this Chatroom")
window.geometry('600x620')


"""画布模块"""
canvas = Canvas(window, height=165, width=600)
image_file = PhotoImage(file='c:\\dog-ring.png')
image = canvas.create_image(0, 0, anchor='nw', image=image_file)
canvas.pack(side='top')

"""用户名、密码模块"""
flag = False
IDC = "Unknown"
Password = " "
s = socket.socket()  # Create a socket object

def Connect():
    print(account.get()+" "+password.get())
    global IDC, flag, Password
    IDC = account.get()
    Password = hashlib.md5(password.get().encode()).hexdigest()
    status.insert(INSERT, """Connecting to Server...""")
    status.insert(INSERT, """\n"""+"Test the second line")
    dataString = account.get() + " " + password.get()
    data.insert(INSERT, dataString)
    flag = True

def UpdateStatus(statusStr):
    status.insert(INSERT, """\n"""+statusStr)

def UpdataData(dataStr):
    data.insert(INSERT, """\n"""+dataStr)

Label(window, text='Account: ').place(x=20, y=165)
account = Entry(window, width=25)
account.place(x=80, y=165)
Label(window, text='Password: ').place(x=260, y=165)
password = Entry(window, width=25)
password.place(x=325, y=165)
connect = Button(window, text="Connect", command=Connect).place(x=510, y=165)

"""状态、数据栏模块"""
Label(window, text='Status Bar').place(x=100, y=190)
Label(window, text='Data bar').place(x=400, y=190)
status = scrolledtext.ScrolledText(window, width=40, height=12)
status.place(x=0, y=215)

data = scrolledtext.ScrolledText(window, width=40, height=12)
data.place(x=300, y=215)

"""聊天模块"""
def send():
    global s
    # print(message.get("1.0", 'end-1c'))
    result.insert(INSERT, """\n<YOU>"""+message.get("1.0", 'end-1c'))
    s.send(message.get("1.0", 'end-1c').encode())

Label(window, text='Input your message here').place(x=230, y=379)
message = scrolledtext.ScrolledText(window, width=69, height=2)
message.place(x=2, y=400)
send = Button(window, text="Send", command=send).place(x=510, y=425)
Label(window, text='Massage').place(x=270, y=450)

result = scrolledtext.ScrolledText(window, width=84, height=9)
result.place(x=2, y=470)
# result.insert(INSERT, """Integer posuere erat a ante venenatis dapibus.""")

# ============== Client Program Progress ===================#
def progress():
    global flag, s
    while True:
        if flag:
            s = socket.socket()  # Create a socket object
            host = hostIP # socket.gethostname()  # Get local machine name
            port = 12345  # Reserve a port for your service.
            s.connect((host, port))

            """Step1 send C2AS message to AS server"""
            # print("Start sending authentication requests to AS...")
            UpdateStatus("Start sending requests to AS...")
            IDtgs = '1234'
            TS1 = str(int(time.time()))
            C2AS = IDC+" "+IDtgs+" "+TS1 + " " + Password  # C →AS : IDC|| IDtgs|| TS1
            UpdataData("C2AS="+C2AS)
            # print("sending C2AS to AS...")
            UpdateStatus("sending C2AS to AS...")
            s.send(C2AS.encode('utf-8'))

            """Step2 parse cipertext from AS"""
            AS_ciphertext = s.recv(4096).decode("utf8")  # receive the message from server
            # print("received m2" + AS_ciphertext)
            UpdateStatus("Received cipher message from AS.")
            AS_ciphertext = AS_ciphertext.split("  ")
            AS_cipher = AS_ciphertext[0]
            AS_Signature = AS_ciphertext[1]
            UpdateStatus("Verifying AS Signature...")

            if VerifyASSignature(AS_cipher, AS_Signature):
                UpdateStatus("Verify AS Signature done!")
                (Kctgs, IDtgs, TS2, Lifetime, Tickettgs) = parseAScipher(AS_cipher)
                UpdataData("Kctgs="+Kctgs+"\n"+"IDtgs="+IDtgs+"\n"+"TS2="+TS2+"\n"+"Lifetime"+Lifetime)

                """Step3 Generate Kctgs and Authenticator"""
                Kctgs = generateKctgs(Kctgs)
                UpdateStatus("Generating Kctgs...")
                ADc = hostIP # socket.gethostbyname(socket.gethostname())
                TS3 = str(int(time.time()))
                AuthText = IDC+" "+ADc+" "+TS3  # Authenticator= EKc,tgs[IDc||ADc||TS3]
                UpdataData("Authenticator="+AuthText)
                Authenticator = DESencrypt(Kctgs, AuthText)
                print(Authenticator)

                """Step4 Generate message C2TGS"""
                # C →TGS : IDV|| Tickettgs|| Authenticator
                IDv = '4567'
                C2TGS = IDv+"  "+Tickettgs+"  "+str(Authenticator)
                # print("C2TGS = " + C2TGS)
                UpdataData("C2TGS = " + C2TGS)
                s.close()

                """Step5 Signing C2TGS"""
                UpdateStatus("Signing C2TGS...")
                foC = open("KpC.txt", "r+")  # 可以简化为一个函数
                PriC = foC.readlines()
                Cn = int(PriC[0])
                Cd = int(PriC[2])
                H_ciphertext = hashlib.md5(C2TGS.encode()).hexdigest()
                print(H_ciphertext)
                Signature = RSAencrypt(H_ciphertext, Cn, Cd, 8)
                C2TGS = C2TGS+"   "+str(Signature)
                # print("C2TGS = " + C2TGS)

                """Step6 send C2TGS message to TGS server"""
                UpdateStatus("Sending C2TGS message to TGS server...")
                s = socket.socket()  # Create a socket object
                host = hostIP # socket.gethostname()  # Get local machine name
                port = 50000  # Reserve a port for your service.
                s.connect((host, port))
                s.send(C2TGS.encode('utf-8'))

                TGS2C_cipher = s.recv(4096).decode("utf8")
                print(TGS2C_cipher)
                TGS2C_cipher = TGS2C_cipher.split("  ")
                TGS2C = TGS2C_cipher[0]
                TGS_Signature = TGS2C_cipher[1]
                UpdateStatus("Verifying TGS Signature...")
                # s.close
                if VerifyTGSSignature(TGS2C, TGS_Signature):
                    UpdateStatus("Verify TGS Signature done!")
                    """Step7 Parse TGS2C cipher, get Kcv and Ticketv"""
                    UpdateStatus("Parsing TGS2C cipher...")
                    (Kcv, IDv, TS4, Ticketv) = ParseTGS2C(Kctgs, TGS2C)
                    # print("(Kcv, IDv, TS4, Ticketv) ="+Kcv+" "+IDv+" "+TS4+" "+Ticketv)
                    UpdataData("(Kcv, IDv, TS4, Ticketv) ="+Kcv+" "+IDv+" "+TS4+" "+Ticketv)

                    """Step8 Generate Kcv and Authenticator"""
                    UpdateStatus("Generating Kcv and Authenticator")
                    Kcv = generateKcv(Kcv)
                    TS5 = str(int(time.time()))
                    AuthText = IDC + " " + ADc + " " + TS5  # Authenticator= EKc,tgs[IDc||ADc||TS3]
                    UpdataData("AuthText ="+IDC + " " + ADc + " " + TS5)
                    Authenticator = DESencrypt(Kcv, AuthText)
                    print(Authenticator)

                    """Step8 generate C2SS message"""
                    C2SS = Ticketv + "  " + str(Authenticator)
                    UpdataData("C2SS ="+C2SS)
                    # print(C2SS)

                    """Step9 Signing C2SS"""
                    UpdateStatus("Signing C2SS...")
                    foSS = open("KSS.txt", "r+")  # 可以简化为一个函数
                    KSS = foSS.readlines()
                    SSn = int(KSS[0])
                    SSd = int(KSS[2])
                    H_ciphertext = hashlib.md5(C2SS.encode()).hexdigest()
                    print(H_ciphertext)
                    SS_Signature = RSAencrypt(H_ciphertext, SSn, SSd, 8)
                    C2SS = C2SS + "   " + str(SS_Signature)
                    print("C2SS = " + C2SS)

                    """Step10 send C2SS message to SS"""
                    UpdateStatus("Sending C2SS message to SS...")
                    s = socket.socket()  # Create a socket object
                    host = hostIP # socket.gethostname()  # Get local machine name
                    port = 40000  # Reserve a port for your service.
                    s.connect((host, port))
                    s.send(C2SS.encode('utf-8'))

                    SS2C_cipher = s.recv(1024).decode("utf8")
                    print(SS2C_cipher)
                    SS2C_cipher = SS2C_cipher.split("  ")
                    SS2C = SS2C_cipher[0]
                    SS_Signature = SS2C_cipher[1]
                    UpdateStatus("Verifying SS Signature...")
                    if VerifySSignature(SS2C, SS_Signature):
                        UpdateStatus("Verify Successfully!Enjoy your chatting")
                        if parseSScipher(Kcv, SS2C) == (int(TS5) + 1):
                            while True:

                                # maintains a list of possible input streams
                                sockets_list = [s]

                                try:
                                    Thread(target=inputmessage, args=(s,)).start()
                                except:
                                    print("Thread did not start.")
                                    traceback.print_exc()

                                read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])

                                for socks in read_sockets:
                                    if socks == s:
                                        message1 = socks.recv(2048).decode()
                                        result.insert(INSERT, "\n"+message1)
                                    else:
                                        pass
                                flag = False
        else:
            continue


try:
    Thread(target=progress, args=()).start()
except:
    print("Thread did not start.")
    traceback.print_exc()

window.mainloop()







