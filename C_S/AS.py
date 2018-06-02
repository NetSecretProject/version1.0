import socket  # Import socket module
import traceback
import time
from threading import Thread
from RSA import RSAencrypt, newKey
from DES import DESencrypt
import hashlib

# (n, e, d) = newKey(10 ** 100, 10 ** 101, 50)
# print("generating AS key...")
# fo = open("KpAS.txt", "w")
# fo.write(str(n))
# fo.write('\n')
# fo.write(str(e))  # write public key to the keyfile
# fo.write('\n')
# fo.write(str(d))
# fo.close()

def parse_request(packet):
    packetlist = packet.split(" ")
    IDc = packetlist[0]
    IDtgs = packetlist[1]
    TS1 = packetlist[2]
    return IDc, IDtgs, TS1


def getDESkey():
    fo = open("DESKctgs.txt", "r+")  # 可以更改为随机生成
    Key = fo.readlines()
    Kctgs = Key[0]
    return Kctgs


def generateKctgs(Kctgs):
    Kctgstext = Kctgs[1:len(Kctgs) - 1].split(", ")
    Kctgslist = []
    for Hex in Kctgstext:
        Kctgslist.append(int(Hex, 16))
    return Kctgslist

def client_thread(c, ip, port):
    """Step1 Parse packet from client"""
    client_request = c.recv(5120)
    decoded_input = client_request.decode("utf8").rstrip()  # decode and strip end of line
    (IDc, IDtgs, TS1) = parse_request(decoded_input)
    print("(IDc, IDtgs, TS1) =" + IDc+" "+IDtgs+" "+TS1)

    """Step2 Generate Kc,tgs"""
    Kctgs = getDESkey()
    Kctgslist = generateKctgs(Kctgs)

    """Step3 Generate Ticket"""
    TS2 = str(int(time.time()))
    lifetime = 6000
    ticket = Kctgs+"  "+IDc+"  "+ip+"  "+IDtgs+"  "+TS2+"  "+str(lifetime)+"  "
    print("ticket = "+ticket)
    cipherTicket = DESencrypt(Kctgslist, ticket)  # 采用DES算法，利用Kctgs进行加密ticket
    print("cipherTicket = " + str(cipherTicket))

    """Step4 Generate AS2C"""
    AS2C = Kctgs+"  "+IDtgs+"  "+TS2+"  "+str(lifetime)+"  "+str(cipherTicket)+"  "
    print("AS2C = "+AS2C)
    cipher = DESencrypt(Kctgslist, AS2C)
    ciphertext = str(cipher)

    """Step5 Signing AS2C"""
    # get the public key of the tgs
    foAS = open("KpAS.txt", "r+")  # 可以简化为一个函数
    PriC = foAS.readlines()
    ASn = int(PriC[0])
    ASd = int(PriC[2])

    H_ciphertext = hashlib.md5(ciphertext.encode()).hexdigest()
    print(H_ciphertext)
    Signature = RSAencrypt(H_ciphertext, ASn, ASd, 8)

    """Step6 response to the client"""
    ciphertext = ciphertext+"  "+str(Signature)
    print("AS TO C ciphertext = "+ciphertext)
    print("sending cipher...")
    c.send(ciphertext.encode("utf8"))


def start_AS():
    s = socket.socket()  # Create a socket object
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    host = socket.gethostname()  # Get local machine name
    port = 12345  # Reserve a port for your service.
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
    start_AS()


if __name__ == "__main__":
    main()