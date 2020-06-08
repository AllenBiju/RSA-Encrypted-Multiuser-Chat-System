import socket
import hashlib 
import threading
import time
import rsa as rsa

ser_pub_key=()
tLock = threading.Lock()
shutdown = False


def encrypt(data, private):
    """
    Encrypts incoming data with given private key
    """
    # print("private key used:", private)

    encrypted_data = ""
    for i in range(0, len(data)):
        encrypted_data += str(rsa.endecrypt(ord(data[i]), private[0], private[1])) + ","
    return encrypted_data


def decrypt(data, public):
    """
    Decrypts input integer list into sentences
    """
    # print("Decrypting")
    words = data.split(",")
    decrypted_data = ""
    for i in range(0, len(words) - 1):
        decrypted_data += str(rsa.decode(rsa.endecrypt(words[i], public[0], public[1])))
    decrypted_data = decrypted_data.replace("'b'", "")
    decrypted_data = decrypted_data.replace("b'", "")
    decrypted_data = decrypted_data.replace("'", "")
    # print("Decrypted Data: ",decrypted_data)
    return decrypted_data
    
    
e,d,c=rsa.keygen()
print("Key generated: ",e,d,c)
clt_pub_key = (e,c)
clt_pvt_key = (d,c)



def receving(name, sock):
    while not shutdown:
        try:
            tLock.acquire()
            while True:
                data, addr = sock.recvfrom(1024)
                data = data.decode("utf-8")
                if(data[0] is "`" and data[-1] is "`"):
                    data = data[1:-1].split(",")
                    global ser_pub_key
                    ser_pub_key = (int(data[0]),int(data[1]))
                    print("Key received: ", ser_pub_key)
                    print("Key sent", "`"+str(e)+","+str(c)+"`")
                    pub_key = encrypt("`"+str(e)+","+str(c)+"`",ser_pub_key)
                    s.sendto(pub_key.encode(),server)
                else:
                    # print("Data before decrypt: ", data)
                    # print("Key used for decrypt: ",clt_pvt_key)
                     if("|||" in data):
                        # data =data + "."        
                        # print("The data is:",data)
                        data,data_hash = data.split("|||")
                        # data = data  + "."
                        result = hashlib.sha512(data.encode()) 
                        calc_hash=result.hexdigest()
                        if(calc_hash!=data_hash):
                            print("Hash does not match")
                            continue
                        print("The message received from the server before decryption: ", data)
                        data = decrypt(data,clt_pvt_key)
                        data = decrypt(data,ser_pub_key)
                        # print("Data after decrypt")
                        print (str(data))
        except:
            pass
        finally:
            tLock.release()

host = '127.0.0.1'
port = 0

server = ('127.0.0.1',5000)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
s.setblocking(0)

rT = threading.Thread(target=receving, args=("RecvThread",s))
rT.start()

"""send teh public key first"""


alias = input("Name: ")

s.sendto(str("^"+alias+"^").encode(),server)

message = ""

while message != 'q':
    if message != '':
        msg='{}: {}'.format(alias, message)
        msg = encrypt(msg,clt_pvt_key)
        msg=encrypt(msg,ser_pub_key)
        result = hashlib.sha512(msg.encode())
        final_msg=msg+"|||"+result.hexdigest()
        # print("The finasl message is:",final_msg)
        s.sendto(str(final_msg).encode(),server)
    tLock.acquire()
    message = input(alias + "-> ")
    tLock.release()
    time.sleep(0.2)

shutdown = True
rT.join()
s.close()
