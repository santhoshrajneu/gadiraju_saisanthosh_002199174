from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from binascii import hexlify
from socket import *
import select, string, sys
import os.path
from os import path
import pickle
import os


if path.exists('public_pem.pem') and path.exists('private_pem.pem'):
    print('Public and Private Keys Exists')
else:
    print('No Public and/or Private Key Found, generating new keys')
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()

    private_pem = private_key.exportKey()
    public_pem = public_key.exportKey()


with open('private_pem.pem', 'rb') as private:
    private_pem = private.read()
with open('public_pem.pem', 'rb') as public:
    public_pem = public.read()

private_key = RSA.importKey(private_pem)
public_key = RSA.importKey(public_pem)


client = socket(AF_INET, SOCK_STREAM)
client.connect(('192.168.0.37',50000))
a='connected'
client.send(a.encode())
serverkey=client.recv(1024)

print('Server Key:',serverkey)
print(type(serverkey))
with open('server_pem.pem', 'wb') as server:
    server.write(serverkey)

server_key= RSA.importKey(serverkey)
client.send(public_pem)

while True:
    print("Bob:")
    Data_send = sys.stdin.readline().strip()
    data1 = Data_send.encode()
    if Data_send == 'exit':
        Data_send = Data_send.encode()
        Data_send = server_key.encrypt(Data_send, 32)
        Data_send = pickle.dumps(Data_send)
        client.send(Data_send)
        break

    hbob = SHA256.new(data1)
    hashdbob = hbob.hexdigest()
    hashenbob = hashdbob.encode()
    client.send(hashenbob)

    Data_send = Data_send.encode()
    Data_send = server_key.encrypt(Data_send, 32)
    Data_send = pickle.dumps(Data_send)
    client.send(Data_send)
    print(Data_send)

    hencode = client.recv(1024)

    Data_receive = client.recv(1024)
    Data_receive = pickle.loads(Data_receive)
    Data_receive = private_key.decrypt(Data_receive)
    Data_receive = Data_receive.decode()
    data1 = Data_receive.encode()

    h = SHA256.new(data1)
    hashd = h.hexdigest()
    hencode2 = hashd.encode()

    if hencode == hencode2:
        print("The Signature is Verified")
    else:
        print("The signature is not valid")
    print("Alice:",Data_receive)
    if Data_receive == 'exit':
        break


client.close()

os.remove("server_pem.pem")
