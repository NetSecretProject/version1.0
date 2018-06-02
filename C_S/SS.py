import socket  # Import socket module
import traceback
from threading import Thread
from RSA import RSAdecrypt, RSAencrypt, newKey
from DES import DESdecrypt, DESencrypt
import hashlib

# (n, e, d) = newKey(10 ** 100, 10 ** 101, 50)
# print("generating SS key...")
# fo = open("KSS.txt", "w")
# fo.write(str(n))
# fo.write('\n')
# fo.write(str(e))  # write public key to the keyfile
# fo.write('\n')
# fo.write(str(d))
# fo.close()
list_of_clients = []

def VerifySignature(C2SS, Signature):
    Sigtext = Signature[1:len(Signature) - 1].split(", ")
    Signature = []
    for num in Sigtext:
        Signature.append(int(num))
    foSS = open("KSS.txt", "r+")  # 可以简化为一个函数
    KSS = foSS.readlines()
    SSn = int(KSS[0])
    SSe = int(KSS[1])
    Verify = RSAdecrypt(Signature, SSn, SSe, 8)
    Hash = hashlib.md5(C2SS.encode()).hexdigest()
    if Verify == Hash:
        print("Signature verify successfully")
        return True
    else:
        print("Signature doesn't Match...")
        return False


def parse_request(c2ss):
    c2sslist = c2ss.split("  ")
    ticketv = c2sslist[0]
    authenticator = c2sslist[1]
    return ticketv, authenticator

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


def decryptTicketv(Ticketv):
    Tickettext = Ticketv[1:len(Ticketv) - 1].split(", ")
    Ticketlist = []
    for Num in Tickettext:
        Ticketlist.append(int(Num))
    print(Ticketlist)
    KcvList = [0x94, 0x74, 0xb8, 0xe8, 0xc7, 0x3b, 0xca, 0x7d]
    Ticket = DESdecrypt(KcvList, Ticketlist)
    Ticket = Ticket.split("  ")
    kcv = Ticket[0]
    idc = Ticket[1]
    adc = Ticket[2]
    idv = Ticket[3]
    ts4 = Ticket[4]
    lifetime4 = Ticket[5]
    return kcv, idc, adc, idv, ts4, lifetime4


def decryptAuth(Kcv, Authenticator):
    Kcvtext = Kcv[1:len(Kcv) - 1].split(", ")
    Kcvlist = []
    for Hex in Kcvtext:
        Kcvlist.append(int(Hex, 16))
    Authtext = Authenticator[1:len(Authenticator) - 1].split(", ")
    Authlist = []
    for num in Authtext:
        Authlist.append(int(num))
    Auth = DESdecrypt(Kcvlist, Authlist)
    Auth = Auth.split(" ")
    IDc = Auth[0]
    ADc = Auth[1]
    TS5 = Auth[2]
    return IDc, ADc, TS5


def timeValidation(lifetime4, TS4, TS5):
    validationLifeTime = TS4 + lifetime4
    return validationLifeTime < TS5


def userVerify(lifetime4, TS4, TS5, ADc, ADc2A, IDc, IDcA):
    if timeValidation(lifetime4, TS4, TS5):
        if ADc == ADc2A:
            if IDc == IDcA:
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

def broadcast(message, connection):
    for clients in list_of_clients:
        if clients != connection:
            try:
                clients.send(message.encode())
            except:
                clients.close()

                # if the link is broken, we remove the client
                remove(clients)

def remove(connection):
    if connection in list_of_clients:
        list_of_clients.remove(connection)

def client_thread(c, addr):
    """Step1 Parse packet from client"""
    client_request = c.recv(2048)
    decoded_input = client_request.decode("utf8").rstrip()  # decode and strip end of line
    print(decoded_input)
    C2SSList = decoded_input.split("   ")
    C2SS = C2SSList[0]
    Signature = C2SSList[1]
    if VerifySignature(C2SS, Signature):
        (Ticketv, Authenticator) = parse_request(decoded_input)
        print("(Ticketv, Authenticator) ="+Ticketv+" "+Authenticator)

        """Step2 decrypt Tickettgs """
        print("decrypting Tickettgs...")
        (Kcv, IDc, ADc, IDv, TS4, lifetime4) = decryptTicketv(Ticketv)
        print(Kcv+" "+IDc+" "+ADc+" "+IDv+" "+TS4+" "+lifetime4)

        """Step3  Verify user's legality"""
        (IDcA, ADc2A, TS5) = decryptAuth(Kcv, Authenticator)
        if userVerify(lifetime4, TS4, TS5, ADc, ADc2A, IDc, IDcA):
            Kcv = getDESkey()
            Kcvlist = generateKcv(Kcv)

            """Step4  generate SS2C """
            SS2C = str(int(TS5) + 1)
            cipherSS2C = str(DESencrypt(Kcvlist, SS2C))

            """Step6  Signing SS2C"""
            foSS = open("KSS.txt", "r+")
            KSS = foSS.readlines()
            SSn = int(KSS[0])
            SSd = int(KSS[2])
            H_ciphertext = hashlib.md5(cipherSS2C.encode()).hexdigest()
            print(H_ciphertext)
            Signature = RSAencrypt(H_ciphertext, SSn, SSd, 8)
            cipherSS2C = cipherSS2C + "  " + str(Signature)

            """Step7  send SS2C to client"""
            print(cipherSS2C)
            c.send(cipherSS2C.encode("utf8"))

            """Step8 Begin Chatting"""
            c.send(("Welcome to this chatroom!"+IDc).encode())
            while True:
                try:
                    message = c.recv(2048).decode()
                    if message:

                        """prints the message and address of the
                        user who just sent the message on the server
                        terminal"""
                        print("<" + addr[0] + "> " + message)

                        # Calls broadcast function to send message to all
                        message_to_send = "<" + IDc + "> " + message
                        broadcast(message_to_send, c)

                    else:
                        """message may have no content if the connection
                        is broken, in this case we remove the connection"""
                        remove(c)

                except:
                    continue



def start_SS():
    s = socket.socket()  # Create a socket object
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    host = socket.gethostname()  # Get local machine name
    port = 40000  # Reserve a port for your service.
    s.bind((host, port))  # Bind to the port

    s.listen(5)  # Now wait for client connection.
    print("Socket now listening")

    while True:
        c, addr = s.accept()
        ip, port = str(addr[0]), str(addr[1])
        print("Connected with " + ip + ":" + port)
        list_of_clients.append(c)

        try:
            Thread(target=client_thread, args=(c, addr)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()


def main():
    start_SS()


if __name__ == "__main__":
    main()