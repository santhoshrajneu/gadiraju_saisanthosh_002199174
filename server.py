from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
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
    with open('private_pem.pem',"wb") as private:
        private.write(private_pem)
    with open('public_pem.pem',"wb") as public:
        public.write(public_pem)

with open('private_pem.pem', 'rb') as private:
    private_pem = private.read()
with open('public_pem.pem', 'rb') as public:
    public_pem = public.read()

private_key = RSA.importKey(private_pem)
public_key = RSA.importKey(public_pem)

server = socket(AF_INET, SOCK_STREAM)
server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
server.bind(('', 50000))
server.listen(5)
print ("socket is listening")
while True:
    (port,addr) = server.accept()
    a=port.recv(1024).decode()
    print('Connected to:',a)
    port.send(public_pem)
    clientkey = port.recv(1024)
    with open('client_pem.pem', 'wb') as client:
        client.write(clientkey)
    client_key= RSA.importKey(clientkey)
    while True:

        hallice = port.recv(1024)

        Data_receive = port.recv(1024)
        Data_receive1 = pickle.loads(Data_receive)
        Data_receive2 = private_key.decrypt(Data_receive1)
        Data_receive = Data_receive2.decode()


        data2 = Data_receive.encode() 
        hbob = SHA256.new(data2)
        hashdbob = hbob.hexdigest()
        hashboben = hashdbob.encode()

        if hallice == hashboben:
            print("Signature is Verified")
        else:
            print("Signature is not Valid")

        print('Bob:',Data_receive)
        if Data_receive == 'exit':
            break
        print('Allice:')

        Data_send = sys.stdin.readline().strip()
        data1 = Data_send.encode()
        if Data_send == 'exit':
            Data_send = Data_send.encode()
            Data_send = client_key.encrypt(Data_send, 32)
            Data_send = pickle.dumps(Data_send)
            port.send(Data_send)
            break

        h = SHA256.new(data1)
        hashdallice = h.hexdigest()
        hashenallice = hashdallice.encode()
        port.send(hashenallice)

        Data_send = Data_send.encode()
        Data_send = client_key.encrypt(Data_send, 32)
        Data_send = pickle.dumps(Data_send)
        port.send(Data_send)

    break

port.close()
os.remove("client_pem.pem")
