import socket
import time
import rsa
import hashlib

data =""

key_ring={}
client_names = {}

def encrypt(data, private):
    """
    Encrypts incoming data with given private key
    """
    # print("Key Used to encrypt: ",private,data )

    encrypted_data = ""
    for i in range(0, len(data)):
        encrypted_data += str(rsa.endecrypt(ord(data[i]), private[0], private[1])) + ","
    return encrypted_data


def decrypt(data, public):
    """
    Decrypts input integer list into sentences
    """
    words = data.split(",")
    decrypted_data = ""
    for i in range(0, len(words) - 1):
        decrypted_data += str(rsa.decode(rsa.endecrypt(words[i], public[0], public[1])))
    decrypted_data = decrypted_data.replace("'b'", "")
    decrypted_data = decrypted_data.replace("b'", "")
    decrypted_data = decrypted_data.replace("'", "")
    return decrypted_data
    
#e,d,c=rsa.keygen()
# e,d,c=7,23,187

host = '127.0.0.1'
port = 5000

clients = []

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host,port))
s.setblocking(0)

pu, pr , m = rsa.keygen()

ser_pub_key = "`"+str(pu)+","+str(m)+"`"
ser_pvt_key = (pr,m)


quitting = False
print ("Server Started.")
while not quitting:
    try:
        key_received = False
        name_received = False
        current_data, addr = s.recvfrom(1024)
        # print(current_data, addr)
        
        data = current_data.decode("utf-8")

        # Getting the name for establising connection
        if(data[0] is "^" and data[-1] is "^"):
            print(data[1:-1]+" is Connected")
            name_received = True
            client_names.update({addr: data[1:-1]})
            s.sendto(ser_pub_key.encode(), addr)
        if("|||" in data):
            # data =data + "."        
            # print("The data is:",data)
            data,data_hash = data.split("|||")
            result = hashlib.sha512(data.encode()) 
            calc_hash=result.hexdigest()
            if(calc_hash!=data_hash):
                print("Hash does not match")
                continue

        data = decrypt(data, ser_pvt_key)
        """take the public key from the client and append it to the key ring"""
        if(data[0] is "`" and data[-1] is "`"):
            print(data[1:-2])
            data = data[1:-1].split(",")
            key_ring.update({addr: (int(data[0]),int(data[1]))})
            print("The key_ring stored is: ",{addr: (int(data[0]),int(data[1]))})
            key_received = True
            print("received key")

        # print(data)
        if "Quit" in str(data):
            quitting = True

        if addr not in clients:
            print("new client added")
            clients.append(addr)
            
        data = decrypt(data,key_ring[addr])
        #print (time.ctime(time.time()) + str(addr) + ": :" + str(data))
        print("The hash for the message from ", client_names[addr],"is verified")
        """In this loop the now decrypted data must be encrypted with the respective clients public key"""
        if key_received is False and name_received is False:
            for client in clients:
                if(addr != client):
                    send_data = encrypt(data,ser_pvt_key)
                    send_data = encrypt(send_data,key_ring[client])
                    result = hashlib.sha512(send_data.encode())
                    send_data=send_data+"|||"+result.hexdigest()
                    print("Encrypter message sent to ",client_names[client])
                    s.sendto(send_data.encode(), client)
            print("done sending messages to all users")
    except:
        pass

s.close()
