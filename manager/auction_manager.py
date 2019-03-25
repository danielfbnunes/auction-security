import io
import json
import cgi
import time, _thread
import PyKCS11
import binascii
import base64
import secrets
import os
import re
import socket
import ssl
from _thread import start_new_thread
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding as s_padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from Crypto.Cipher import AES
from datetime import datetime
from os import scandir, path
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR, error as SocketError

# wait from request from the manager
listen_addr = '127.0.0.1'
listen_port = 8080
server_cert = 'managerCertificate.pem'
server_key = 'managerKey.key'
client_ca = 'sioCACertificate.pem'
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
context.load_verify_locations(cafile=client_ca)
bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

# receive data
def recvall(sock):
    BUFF_SIZE = 4096
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

class AuctionInfo:
    manager_pvk = None
    user_roots = {}
    roots = {}
    clients_keys = {}

# handle requests
def message_execute(message):
    if message['type'] == 'auction_create':
        try:
            # write validation code
            with open("validation_"+str(message['auction_id'])+".py", "w") as myfile:
                myfile.write(message['validation'])

            # generate cipher key for auction
            aes_key = generate_aes()

            # save key to file
            with open ("auction_keys", "ab") as auction_keys_file:
                auction_keys_file.write( str.encode(str(message['auction_id']))  + b"\t" + aes_key +  b"\n")
                auction_keys_file.close()
                return {'success' : 'yes'}
        except:
            print("[Error] Creating auction on manager!")
            return {'success' : 'no'}
            
    if message['type'] == 'bid':
        user_validation = message["from"]
        bid_validation = message["bid"]
        auction_id = message["auction_id"]
        blockchain = message["blockchain"]
        blockchain_list =  json.loads(blockchain)
        # get managers keys
        auction_keys = dict() 
        with open ("auction_keys", "rb") as auction_keys_file:
            content = auction_keys_file.read()
            auctions = content.split(b"\n")
            # iterate over all auctions
            for a in auctions[:-1]:
                a_id = (a.split(b"\t")[0]).decode("utf-8")
                a_pw = a.split(b"\t")[1] 
                auction_keys[a_id] = a_pw

        man_key = auction_keys[auction_id]
        bids = []
        # get that from the blockchain from bid validation
        if len(blockchain_list)>1:
            bids = [ (block["Data"]["user"], block["Data"]["bid"], block["Data"]["manager_nonce"]) for  block in blockchain_list[1:]]
            new_list = []
            for u, b, nonce in bids:
                nonce = base64.b64decode(nonce)
                user = None
                bid = None
                if "user" in message["anonymous_fields"]:
                    user = AESCCM(man_key).decrypt(nonce, base64.b64decode(u), None)
                else:
                    user = u
                if "bid" in message["anonymous_fields"]:
                    bid = AESCCM(man_key).decrypt(nonce, base64.b64decode(b), None)
                else:
                    bid = b
                new_list.append((user,bid))
            bids = new_list

        variables4validation = {"bids": bids , "auction_id" : int(auction_id)}
        # generate nonce for ciphering
        nonce = os.urandom(13)
        # get managers auction key
        aesccm = AESCCM(man_key)
        # user is ciphered

        # deal with anonymous fields
        returned_user = None
        returned_bid = None
        ciphered_bid = None
        ciphered_user = None
        if "user" in message["anonymous_fields"]:
            ciphered_user = aesccm.encrypt(nonce, base64.b64decode(user_validation), None)
            returned_user = base64.b64encode(ciphered_user).decode()
            variables4validation["user"] = base64.b64decode(user_validation)
        else:
            returned_user = user_validation
            variables4validation["user"] = user_validation
        
        if "bid" in message["anonymous_fields"]:
            ciphered_bid = aesccm.encrypt(nonce, base64.b64decode(bid_validation), None)
            returned_bid = base64.b64encode(ciphered_bid).decode()
            variables4validation["bid"] = base64.b64decode(bid_validation)
        else:
            returned_bid = base64.b64decode(bid_validation).decode()
            variables4validation["bid"] = base64.b64decode(bid_validation).decode()

        cert_key = base64.b64decode(message["cert_key"])
        cert_key = aesccm.encrypt(nonce, cert_key, None)

        cert_nonce = base64.b64decode(message["cert_nonce"])
        cert_nonce = aesccm.encrypt(nonce, cert_nonce, None)

        script_locals = dict()
        print("Variables for validation:", variables4validation)
        print("Auction id :", message['auction_id'])
        exec(open("./validation_"+str(message['auction_id'])+".py").read(), variables4validation, script_locals)
        if script_locals["valid"]:
            print("Valid bid")
            return {'type' : 'OK',  "puzzle_difficulty": len(blockchain_list) ,"manager_nonce": base64.b64encode(nonce).decode(), "cert_key":base64.b64encode(cert_key).decode(), "cert_nonce":base64.b64encode(cert_nonce).decode(), "user": returned_user, "bid":returned_bid}
        else:
            print("Invalid bid")
            return {'type' : 'NOK'}

    if message['type'] == 'request_auction_key':
        auction_id = message["auction_id"]
        # get managers key
        auction_keys = dict() 
        with open ("auction_keys", "rb") as auction_keys_file:
            content = auction_keys_file.read()
            auctions = content.split(b"\n")
            print("Auction keys:", auctions[:-1])
            # iterate over all auctions
            for a in auctions[:-1]:
                a_id = (a.split(b"\t")[0]).decode("utf-8")
                a_pw = a.split(b"\t")[1] 
                auction_keys[a_id] = a_pw

        man_key = auction_keys[str(auction_id)]
        response = {"key": base64.b64encode(man_key).decode()}
        return response
    return None

# get cert from file and check its date validation
def getCert(file, name):
    f = open(file, "rb")
    cert = x509.load_der_x509_certificate(f.read(), default_backend())
    if validateDate(cert.not_valid_before, cert.not_valid_after):
        return cert
    return None

# validate expire date of certificate
def validateDate(before, after):
    return datetime.now() >= before and datetime.now() <= after

# create chain of certificates for certificate validation
def buildIssuers(chain, cert):
    chain.append(cert)
    issuer = cert.issuer
    subject = cert.subject
    if issuer == subject and subject in AuctionInfo.roots:
        print("Chain completed")
        return True
    if issuer in AuctionInfo.user_roots:
        return buildIssuers(chain, AuctionInfo.user_roots[issuer])
    if issuer in AuctionInfo.roots:
        return buildIssuers(chain, AuctionInfo.roots[issuer])
    print("Unable to create trust chain")
    return False

# Used to generate an AES key
def generate_aes():
    return AESCCM.generate_key(bit_length=128)

# get private from manager
with open('managerKey.key', 'rb') as pem_in:
    pemlines = pem_in.read()
AuctionInfo.manager_pvk = load_pem_private_key(pemlines, None, default_backend())

print("Waiting for client")
def manager_thread(conn):
    while True:
        # try:
        data = recvall(conn)
        if data:
            s = data.decode("utf-8")
            data = json.loads(s)
            resp = message_execute(data)
            if resp != None:
                resp_json = json.dumps(resp)
                conn.send(bytes(resp_json,"utf-8"))
        # except SocketError:
        pass

# manager lifecycle
while True:
    newsocket, fromaddr = bindsocket.accept()
    conn = context.wrap_socket(newsocket, server_side=True)
    start_new_thread(manager_thread, (conn,))

    