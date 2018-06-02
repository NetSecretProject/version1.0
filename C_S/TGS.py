import hashlib
import socket  # Import socket module
import traceback
import time
from threading import Thread
from RSA import RSAdecrypt, RSAencrypt, newKey
from DES import DESdecrypt, DESencrypt

# (n, e, d) = newKey(10 ** 100, 10 ** 101, 50)
# print("generating TGS key...")
# fo = open("KpTGS.txt", "w")
# fo.write(str(n))
# fo.write('\n')
# fo.write(str(e))  # write public key to the keyfile
# fo.write('\n')
# fo.write(str(d))
# fo.close()

def parse_request(packet):
    packetlist = packet.split("  ")
    IDv = packetlist[0]
    Tickettgs = packetlist[1]
    Authenticator = packetlist[2]
    return IDv, Tickettgs, Authenticator


def decryptTicket(Tickettgs):
    Tickettext = Tickettgs[1:len(Tickettgs) - 1].split(", ")
    Ticketlist = []
    for Num in Tickettext:
        Ticketlist.append(int(Num))
    print(Ticketlist)  # Tickettgs= EKtgs[Kc,tgs|| IDC|| ADC|| IDtgs|| TS2|| Lifetime2]
    KctgsList = [0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59]
    Ticket = DESdecrypt(KctgsList, Ticketlist)
    Ticket = Ticket.split("  ")
    Kctgs = Ticket[0]
    IDc = Ticket[1]
    ADc = Ticket[2]
    IDtgs = Ticket[3]
    TS2 = Ticket[4]
    lifetime2 = Ticket[5]
    return Kctgs, IDc, ADc, IDtgs, TS2, lifetime2


def decryptAuth(Kctgs, Authenticator):
    Kctgstext = Kctgs[1:len(Kctgs) - 1].split(", ")
    Kctgslist = []
    for Hex in Kctgstext:
        Kctgslist.append(int(Hex, 16))
    Authtext = Authenticator[1:len(Authenticator) - 1].split(", ")
    Authlist = []
    for num in Authtext:
        Authlist.append(int(num))
    Auth = DESdecrypt(Kctgslist, Authlist)
    Auth = Auth.split(" ")
    IDc = Auth[0]
    ADc = Auth[1]
    TS3 = Auth[2]
    return IDc, ADc, TS3


def timeValidation(lifeTime, TS2, TS3):
    validationLifeTime = TS2 + lifeTime
    return validationLifeTime < TS3


def ADValidation(ADc, ADc2A):
    return ADc == ADc2A


def IDValidation(IDc, IDcA):
    return IDc == IDcA


def userVerify(lifetime2, TS2, TS3, ADc, ADc2A, IDc, IDcA):
    if timeValidation(lifetime2, TS2, TS3):
        if ADValidation(ADc, ADc2A):
            if IDValidation(IDc, IDcA):
                return True
            else:
                print("User ID Verify failed!")
                return False
        else:
            print("User AD Verify failed!")
            return False
    else:
        print("Time Verify failed!")
        return False


def getDESkey():
    fo1 = open("DESKcv.txt", "r+")
    Key = fo1.readlines()
    Kcv = Key[0]
    return Kcv


def generateKcv(Kcv):
    Kcvtext = Kcv[1:len(Kcv) - 1].split(", ")
    Kcvlist = []
    for Hex in Kcvtext:
        Kcvlist.append(int(Hex, 16))
    return Kcvlist


def generateKctgs(Kctgs):
    Kctgstext = Kctgs[1:len(Kctgs) - 1].split(", ")
    Kctgslist = []
    for Hex in Kctgstext:
        Kctgslist.append(int(Hex, 16))
    return Kctgslist


def VerifySignature(C2TGS, Signature):
    Sigtext = Signature[1:len(Signature) - 1].split(", ")
    Signature = []
    for num in Sigtext:
        Signature.append(int(num))
    foC = open("KpC.txt", "r+")  # 可以简化为一个函数
    PriC = foC.readlines()
    Cn = int(PriC[0])
    Ce = int(PriC[1])
    Verify = RSAdecrypt(Signature, Cn, Ce, 8)
    Hash = hashlib.md5(C2TGS.encode()).hexdigest()
    if Verify == Hash:
        print("Signature verify successfully")
        return True
    else:
        print("Signature doesn't Match...")
        return False

def client_thread(c, ip, port):
    """Step1 Parse packet from client"""
    client_request = c.recv(2048)
    decoded_input = client_request.decode("utf8").rstrip()  # decode and strip end of line
    C2TGSList = decoded_input.split("   ")
    C2TGS = C2TGSList[0]
    Signature = C2TGSList[1]
    if VerifySignature(C2TGS, Signature):
        (IDv, Tickettgs, Authenticator) = parse_request(decoded_input)
        print("(IDv, Tickettgs, Authenticator) = " + IDv+" "+Tickettgs+" "+Authenticator)

        """Step2 decrypt Tickettgs """
        print("decrypting Tickettgs...")
        (Kctgs, IDc, ADc, IDtgs, TS2, lifetime2) = decryptTicket(Tickettgs)
        print(Kctgs+" "+IDc+" "+ADc+" "+IDtgs+" "+TS2+" "+lifetime2)

        """Step3  Verify user's legality"""
        (IDcA, ADc2A, TS3) = decryptAuth(Kctgs, Authenticator)
        if userVerify(lifetime2, TS2, TS3, ADc, ADc2A, IDc, IDcA):

            # generate DES key which shared by the client and the server
            Kcv = getDESkey()
            Kcvlist = generateKcv(Kcv)

            """Step4  generate Ticketv"""
            TS4 = str(int(time.time()))
            lifetime4 = 6000
            Ticketv = Kcv+"  "+IDc+"  "+ADc+"  "+IDv+"  "+TS4+"  "+str(lifetime4)+"  "
            print(Ticketv)
            cipherTicketv = DESencrypt(Kcvlist, Ticketv)
            print("cipherTicketv = "+str(cipherTicketv))

            """Step5  generate TGS2C"""
            TGS2C = Kcv+"  "+IDv+"  "+TS4+"  "+str(cipherTicketv)+"  "
            print("TGS2C = " + TGS2C)
            # Generate Kctgs and TGS2C cipher
            Kctgs = generateKctgs(Kctgs)
            cipherTGS2C = str(DESencrypt(Kctgs, TGS2C))

            """Step6  Signing TGS2C"""
            foTGS = open("KpTGS.txt", "r+")  # 可以简化为一个函数
            KTGS = foTGS.readlines()
            TGSn = int(KTGS[0])
            TGSd = int(KTGS[2])
            H_ciphertext = hashlib.md5(cipherTGS2C.encode()).hexdigest()
            print(H_ciphertext)
            Signature = RSAencrypt(H_ciphertext, TGSn, TGSd, 8)
            cipherTGS2C = cipherTGS2C + "  " + str(Signature)

            """Step7  send TGS2C to client"""
            print(cipherTGS2C)
            c.send(cipherTGS2C.encode("utf8"))


def start_TGS():
    s = socket.socket()  # Create a socket object
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    host = socket.gethostname()  # Get local machine name
    port = 50000  # Reserve a port for your service.
    s.bind((host, port))  # Bind to the port

    s.listen(5)  # Now wait for client connection.
    print("Socket now listening")

    while True:
        c, addr = s.accept()
        ip, port = str(addr[0]), str(addr[1])
        print("Connected with " + ip + ":" + port)

        try:
            Thread(target=client_thread, args=(c, ip, port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

def main():
    start_TGS()


if __name__ == "__main__":
    main()