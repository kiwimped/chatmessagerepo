import socket
import rsa
import hashlib
import hmac
from Crypto.Cipher import AES 

from Crypto.Random import get_random_bytes 
from Crypto.Util.Padding import pad 
from Crypto.Util.Padding import unpad 
from base64 import b64encode
from base64 import b64decode

def getAAesKey():
        key = get_random_bytes(16)
        return key
   
def encryptAes(plainText, key):
        #Update this method to complete the encryption using the AES encryption method
        paddedText = pad(plainText, AES.block_size)#Padding the plain text to align AES block size so that the encrypted message can be fitted de
        aesCipher = AES.new(key, AES.MODE_ECB) #Creating the AES cipher
        return aesCipher.encrypt(paddedText) #Returning the ciphered text

def decryptAes(cipheredText, key):
        #update this method to complete the encryption using the AES descryption method
        aesCipher = AES.new(key, AES.MODE_ECB)
        plainText =unpad(aesCipher.decrypt(cipheredText),AES.block_size)
        return plainText #Returning the plain text
    
publicKey, privateKey = rsa.newkeys(1024)
pk = None
key = get_random_bytes(16)

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#client.connect(("10.111.36.185",9999))
client.connect(("10.0.0.22",9999))

#send public key to reciver(server) and encryted aes key for the message
pk = rsa.PublicKey.load_pkcs1(client.recv(1024))
client.send(publicKey.save_pkcs1("PEM"))
ekey = rsa.encrypt(key,pk)
client.send(ekey)

done = False
filename = './msg_log.txt'



# Loop sends key and message between each other and connection is check for integrity using hash
# if hash is matching, continue. If not, break connection
while not done:
    

    message = input("Message: ").encode()
    enmessage = encryptAes(message,key)
    SenderMAC = hmac.new(key,enmessage,hashlib.sha256).hexdigest()


    print(enmessage)
    client.send(enmessage)
    client.send(SenderMAC.encode())

    demessage = client.recv(1024)
    demac = client.recv(64).decode()
    recvmac = hmac.new(key,demessage,hashlib.sha256).hexdigest()
    
    if hmac.compare_digest(demac,recvmac):
        print(True)
        msg = decryptAes(demessage,key).decode()
    

        if msg == 'quit':
            done = True
        else:

            print(msg)
            with open(filename,'a') as file:
                file.write("Server: " +  b64encode(enmessage).decode() + '\n')
    else:
        print(False)
        print("MESSAGE BAD")
        done = True

file.close()
        
