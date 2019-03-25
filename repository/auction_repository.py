import io
import json
import cgi
import time, _thread
import PyKCS11
import binascii
import base64
import os
import re
import socket
import ssl
import copy
# imports for otp
import sys
import secrets
import time
# imports for pickle
import _pickle as pickle
from pathlib import Path
# import for SinchSMS
from sinchsms import SinchSMS
from _thread import start_new_thread
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding
from cryptography.hazmat.primitives import padding as s_padding
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from os import scandir, path
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR, error as SocketError
from blockchain import BlockChain
from json import JSONEncoder



# connection from repository to manager
def connect_manager():
    man_addr = '127.0.0.1'
    man_port = 8080
    server_hostname = 'localhost'
    server_ca = 'sioCACertificate.pem'
    client_key = 'repositoryKey.key'
    client_cert = 'repositoryCertificate.pem'
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    context.load_verify_locations(cafile=server_ca)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    man_conn =  context.wrap_socket(s, server_side=False, server_hostname=server_hostname)
    man_conn.connect((man_addr, man_port))
    return man_conn

man_conn = connect_manager()

# receive all data
def recvall(sock):
    BUFF_SIZE = 4096
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

# listen to request on port 8081
listen_addr = '127.0.0.1'
listen_port = 8081
server_cert = 'repositoryCertificate.pem'
server_key = 'repositoryKey.key'
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
bindsocket = socket.socket()
bindsocket.bind((listen_addr, listen_port))
bindsocket.listen(5)

# roots and user_roots for certificate validation  
global_roots = {}
global_user_roots = {}

class AuctionInfo:
    def __init__(self):
        self.repository_pvk = None
        self.auction_id = 0
        self.clients_keys = {}
        self.auctions = {}
        self.otp = None
        self.global_id = 0

# load pickle on server restore
def load_pickle(f): 
    # Load Pickle File
    my_file = Path(f)
    if my_file.is_file():
        myAuction = pickle.load( open(f,"rb") )
        # reconvert
        myAuction.repository_pvk = serialization.load_pem_private_key(
            myAuction.repository_pvk,
            password=None,
            backend=default_backend()
        )
        myAuction.global_id = 0
        # end all auctionskill
        for k in myAuction.auctions.keys():
            myAuction.auctions[k][2]["open"] = "false"
    else:
        myAuction = AuctionInfo()
    return myAuction

# save pickle on change of class Auction Info
def save_pickle(f): 
    pem = myAuction.repository_pvk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    tmpkey = copy.copy(myAuction.repository_pvk)
    myAuction.repository_pvk = pem
    pickle_file = open("auction.pickle","wb")
    pickle.dump(myAuction, pickle_file)
    pickle_file.close()
    myAuction.repository_pvk = tmpkey

# load pickle
myAuction = load_pickle("auction.pickle")

# create digest of data
def digest_func(data):
    sha = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha.update(data)
    return sha.finalize()

# handle messages from the client
def message_execute(message):
    if message["type"] == "auction_create":
        # update auction id
        myAuction.auction_id += 1
        # create auction info to display on repo
        auction_info = {"open" : "yes", "owner" : message['from'], "auction_id": myAuction.auction_id, "auction_name" : message["auction_name"]}
        # write function of difficulty block modification for this auction
        with open("dif_"+str(myAuction.auction_id)+".py", "w") as myfile:
                myfile.write(message['function'])
        # send infos to manager
        # manager will create a specific  key for each auction
        data = {"from": message['from'], "type" : "auction_create", "auction_id": myAuction.auction_id, "validation": message["validation"]}
        data_json = json.dumps(data)
        man_conn.send(bytes(data_json,"utf-8"))
        # receive answer
        response = recvall(man_conn)
        response_json = json.loads(response.decode("utf-8"))
        if response_json['success'] == "yes":
            print("Manager created the auction key")
            # create a new block and send it to the cliente
            # the client will have to solve the cryptopuzzle
            bc = BlockChain()
            # information to be inserted in the first block
            initial_info = {"puzzle_difficulty": message["auction_difficulty"], "creator":message['from'], "cert":message["cert"], "signature":message["signature"], "anonymous_fields":message["auction_anonymous_fields"],  "auction_name":message["auction_name"], "auction_id":myAuction.auction_id, "type":message["auction_type"],  "description":message["auction_description"],  "creator_key": message["auction_key"] }
            block = bc.generate_new_block(initial_info)
            # save block to stack
            auctions_temp_stack = [block]
            # save blockchain
            myAuction.auctions[myAuction.auction_id] = (bc,auctions_temp_stack,auction_info)
            # save to pickle
            save_pickle("auction.pickle")
            # create thread with the auction
            try:
                # initiate timed task
                _thread.start_new_thread(time_func, (message["timer"], myAuction.auction_id))
            except:
                print ("Error: unable to start thread")
            # send block to be solved by the client
            return {"block" : json.dumps(block.to_json()), 'data' : myAuction.auction_id}
        else:
            return {"block" : None, 'data' : myAuction.auction_id}

    
    # get auction info
    if message["type"] == "get_auction_info":
        # get auction id
        auction_id = message["auction_id"]
        # access the block chain and retrieve the data (json)
        block_info = myAuction.auctions[auction_id][0].get_auction_info()
        print("Sending info from auction " + str(block_info['auction_id']))
        return block_info

    # get auction entire info
    if message["type"] == "get_auction":
        # get auction id
        auction_id = message["auction_id"]
        # access the block chain and retrieve the data (json)
        infos = myAuction.auctions[auction_id][0].get_auction()
        return infos

    # validate solved block
    if message["type"] == "solved_block":
        try:
            block_json = json.loads(message["solution"])
            data_json = block_json["Data"]
            # check if auction is still open when the user sets the bid
            if myAuction.auctions[data_json["auction_id"]][2]['open'] == 'false' and 'send_keys' not in message:
                return {"block" : None}
            auction_id = data_json["auction_id"]
            tmp_block = myAuction.auctions[auction_id][1].pop(0)
            tmp_block.puzzle_solution = block_json["Solution"]
            tmp_block.nonce = block_json["Nonce"]
            tmp_block.timestamp = block_json["Timestamp"]
            
            # get blockchain and insert new block, validating it 
            bc = myAuction.auctions[auction_id][0]
            ret = bc.insert_solved_block(tmp_block)
            print("Inserted_block at position", ret.index)

            signature = myAuction.repository_pvk.sign(
                bytes(ret.puzzle_solution, 'utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
            # sign block and return it as a receipt
            b = ret.to_json()
            b["Solution"] = ret.puzzle_solution

            # save to pickle
            save_pickle("auction.pickle")

            return {"block" : json.dumps(b), "solution": ret.puzzle_solution, "signature" : base64.b64encode(signature).decode()} 
        except:
            print("Solution doesn't match")

    # validate bid
    if message["type"] == "bid":  
        # add anonymous_fields
        auction_infos = myAuction.auctions[int(message["auction_id"])][0].get_auction_info()
        message["anonymous_fields"] = auction_infos["anonymous_fields"]
        # add auction_difficulty
        message["puzzle_difficulty"] = auction_infos["puzzle_difficulty"]
        # add chain
        message["blockchain"] = json.dumps(myAuction.auctions[int(message["auction_id"])][0].get_chain_serialized())
        data_json = json.dumps(message)
        # send bid to be validated by manager
        man_conn.send(bytes(data_json,"utf-8"))
        response = recvall(man_conn)
        d_json = json.loads(response.decode("utf-8"))
        if d_json['type'] == "OK":
            # get the blockchain
            bc = myAuction.auctions[int(message["auction_id"])][0]
            # get blocks info
            # "puzzle_difficulty": d_json["puzzle_difficulty"],
            info = {"puzzle_difficulty":auction_infos["puzzle_difficulty"]  , "auction_id":int(message["auction_id"]), "signature": message["signature"], "user": d_json["user"], "bid": d_json["bid"], "user_certificate":message["cert"], "cert_key" : d_json['cert_key'], "cert_nonce" : d_json['cert_nonce'], "manager_nonce":d_json["manager_nonce"] }
            # create pre block
            block = bc.generate_new_block(info)
            script_locals = dict()
            variables = {"block": block, "blockchain": bc}
            exec(open("./dif_" + message["auction_id"] + ".py").read(), variables, script_locals)
            # get the block validated by the manager and with the keys used
            block = script_locals["block"]
            # get difficulty for the block dynamically
            difficulty = script_locals["difficulty"]
            print("Cryptopuzzle difficulty:", difficulty)
            # save pre-block on the stack
            myAuction.auctions[int(message["auction_id"])][1].append(block)
            # save to pickle
            save_pickle("auction.pickle")
            # send block to the client
            return {"block" : json.dumps(block.to_json()), 'data' : int(message["auction_id"])} # , "difficulty":3}
        else:
            return {"block" : "Invalid Block", 'data' : int(message["auction_id"])}

    # insert last block
    if message["type"] == "insert_last_block":
        auction_id = int(message["auction_id"])
        # ask the manager for his auction key
        man_message = {"type":"request_auction_key", "auction_id" : auction_id}
        data_json = json.dumps(man_message)
        man_conn.send(bytes(data_json,"utf-8"))
        response = recvall(man_conn)
        d_json = json.loads(response.decode("utf-8"))
        # get default difficulty
        default_puzzle_difficulty = (myAuction.auctions[int(message["auction_id"])][0].get_chain_serialized()[0])["Data"]["puzzle_difficulty"]
        # build data for block
        info = {"puzzle_difficulty": default_puzzle_difficulty, "auction_id": auction_id, "cert" : message["cert"], "signature" : message["signature"], "owner_key":message["owner_key"], "manager_key":d_json["key"]}
        # get the blockchain
        bc = myAuction.auctions[auction_id][0]
        # create pre block
        block = bc.generate_new_block(info)
        # save pre-block on the stack
        myAuction.auctions[int(message["auction_id"])][1].append(block)
        # save to pickle
        save_pickle("auction.pickle")
        # send block to the client
        print("Inserted last block")
        return {"block" : json.dumps(block.to_json()), 'data' : auction_id}

    # end auction
    if message["type"] == "endAuction":
        myAuction.auctions[message["auction_id"]][2]["open"] = "false"
        # save to pickle
        save_pickle("auction.pickle")

    # list open auctions (doesn't matter the owner)
    if message["type"] == "listOpen":
        return listAuctions(None, True, False)
    
    # list open auctions from a certain owner
    if message['type'] == "listMyOpen":
        return listAuctions(message['serial'], True, False)

    # list closed auctions from a certain owner
    if message['type'] == "listMyClosed":
        return listAuctions(message['serial'], False, True)
    
    # list open / closed auctions (doesn't matter the owner)
    if message["type"] == "listOpenClosed":
        return listAuctions(None, True, True)
    
    # request chain
    if message["type"] == "requestChain":
        chain4client = (myAuction.auctions[int(message['auction_id'])][0]).get_chain4client()
        # construct the message signing a digest from the blockchain
        # the client can verify the signature from the repo
        message= {}
        message["blockchain"] =json.dumps(chain4client)
        digest = digest_func(bytes(message["blockchain"], 'utf-8'))
        message["digest"] = base64.b64encode(digest).decode()
        message["digest_signature"] = base64.b64encode(myAuction.repository_pvk.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )).decode()
        return message

    if message["type"] == "otp_needed":
        if len(sys.argv) > 1 and sys.argv[1] == "two_factor":
            # define session OTP
            otp = ""
            while len(otp) < 6:
                n = secrets.randbelow(10)
                otp += str(n)
            
            myAuction.otp = otp
            # send sms to client
            number = '+351911148909'
            m = "OTP to access repository: " + otp
            client = SinchSMS("41da1648-fe23-49d2-9ff6-77d85ab9fe03", "fZmQ4p54RE6oDiklITnS6w==")
            print("Sending '%s' to %s" % (m, number))
            client.send_message(number, m)  
            # send response
            resp = {'response' : 'yes'}
            resp = json.dumps(resp)
            conn.send(bytes(resp, 'utf-8'))
        else:
            # send response
            resp = {'response' : 'no'}
            resp = json.dumps(resp)
            conn.send(bytes(resp, 'utf-8'))

    # save key sent from the client
    if message["type"] == "save_session_key":
        # validate certificate client
        cert = x509.load_pem_x509_certificate(base64.b64decode(message['cert']), backend=default_backend())
        if validateDate(cert.not_valid_before, cert.not_valid_after):
            global_user_roots[cert.subject] = cert
        for entry in scandir("./cc_certs/"):
            try:
                c = getCert(path.join("./cc_certs/",entry.name), "./cc_certs/" + str(entry.name))
                if c != None:
                    subject = c.subject
                    global_roots[subject] = c
            except:
                print("Cert error")
        val = buildIssuers([], cert)
        if val:
            print('Valid certificate!')
            if cert.public_key().verify(base64.b64decode(message['signed_key']), base64.b64decode(message['ciphered_key']), padding.PKCS1v15(), SHA1()) == None and cert.public_key().verify(base64.b64decode(message['signed_nonce']), base64.b64decode(message['ciphered_nonce']), padding.PKCS1v15(), SHA1()) == None:
                print("Valid RSA")
                ciphered_key = base64.b64decode(message['ciphered_key'])
                ciphered_nonce = base64.b64decode(message['ciphered_nonce'])
                # get otp sent
                if len(sys.argv) > 1 and sys.argv[1] == "two_factor":
                    ciphered_otp = base64.b64decode(message['ciphered_otp'])
                    otp = myAuction.repository_pvk.decrypt(
                    ciphered_otp,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    ))
                    otp = otp.decode("utf-8")
                    print("Sent OTP:", otp)
                    # if otp isnt correct
                    if myAuction.otp != otp :
                        print("Invalid OTP")
                        resp = {'response' : 'INVALID OTP'}
                        resp = json.dumps(resp)
                        conn.send(bytes(resp, 'utf-8'))
                # get key sent
                key = myAuction.repository_pvk.decrypt(
                    ciphered_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    ))
                # get nonce sent
                nonce = myAuction.repository_pvk.decrypt(
                    ciphered_nonce,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                myAuction.global_id += 1
                myAuction.clients_keys[myAuction.global_id] = key
                # save to pickle
                save_pickle("auction.pickle")

                return {'response' : 'AES-CCM SAVED', 'global_id' : myAuction.global_id}, myAuction.global_id 
            else:
                return {'response' : 'AES-CCM NOT SAVED'}
        else:
            print('Invalid certificate!')
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
    if issuer == subject and subject in global_roots:
        print("Chain completed")
        return True
    if issuer in global_user_roots:
        return buildIssuers(chain, global_user_roots[issuer])
    if issuer in global_roots:
        return buildIssuers(chain, global_roots[issuer])
    print("Unable to create trust chain")
    return False

# get repository private key 
with open('repositoryKey.key', 'rb') as pem_in:
    pemlines = pem_in.read()
myAuction.repository_pvk = load_pem_private_key(pemlines, None, default_backend())

# returns a list of auctions regarding the clients request
def listAuctions(owner=None, opened=None, closed=None):
    lst = []
    for bc,stack,info in myAuction.auctions.values():
        b = False
        if owner != None and info['owner'] == owner:
            if opened == True and info['open'] == 'yes':
                b = True
            if closed == True and info['open'] == 'false':
                b = True
        elif owner == None:
            if opened == True and info['open'] == 'yes':
                b = True
            if closed == True and info['open'] == 'false':
                b = True
        if b:
            lst.append(info)
    # construct message to present to the client
    final_str = ""
    o_or_c = lambda x : 'OPENED' if x == 'yes' else 'CLOSED'
    for l in lst:
        final_str += '\t' + str(l['auction_id']) + ") " + l['auction_name'] + ' [' + o_or_c(l['open']) + ']' + '\n'
    return {'data': final_str}

# thread that runs a auction for a certain time or until a request to end a auction from the owner
def time_func(timer, auction_id):
    auction_timer = timer
    if auction_timer <= 0:
        while myAuction.auctions[auction_id][2]['open'] == 'yes':
            print(myAuction.auctions[auction_id][2], '[NO END]')
            time.sleep(1)
    else:
        while auction_timer > 0 and myAuction.auctions[auction_id][2]['open'] == 'yes':
            print(myAuction.auctions[auction_id][2], '[LEFT : ' + str(auction_timer) + ']')
            auction_timer-=1
            time.sleep(1)
    myAuction.auctions[auction_id][2]["open"] = "false"
    print(myAuction.auctions[auction_id][2])
    print("[" + myAuction.auctions[auction_id][2]["auction_name"] + "] end")

# repo thread
print("Waiting for client")
def repo_thread(conn):
    while True:
        try:
            # get data
            data = recvall(conn)
            if data:
                s = data.decode("utf-8")
                data = json.loads(s)
                # first messages from the client
                # This message is not secure
                if "type" in data.keys() and (data["type"] == "otp_needed" or data["type"] == "requestId"):
                    print("MESSAGE REQUEST:", data["type"])
                    resp = message_execute(data)
                    if resp != None:
                        resp_json = json.dumps(resp)
                        conn.send(bytes(resp_json, 'utf-8'))
                # deal with the message to save session key
                elif 'from' not in data.keys():
                    print("MESSAGE REQUEST:", data["type"])
                    resp, serial = message_execute(data)
                    if resp != None:
                        resp_json = json.dumps(resp)
                        nonce = os.urandom(13)
                        aesccm = AESCCM(myAuction.clients_keys[int(serial)])
                        b = aesccm.encrypt(nonce, bytes(resp_json, 'utf-8'), None)
                        data_str = json.dumps({"nonce": base64.b64encode(nonce).decode(), "data" : base64.b64encode(b).decode()})
                        conn.send(bytes(data_str, 'utf-8'))
                # deal with all the other messages with the structure : "{ from : id , data : encrypted_data , nonce : nonce used }"
                else:
                    aesccm = AESCCM(myAuction.clients_keys[data['from']])
                    d = aesccm.decrypt(base64.b64decode(data['nonce']), base64.b64decode(data['data']), None)
                    j = json.loads(d.decode())
                    print("MESSAGE REQUEST:", j["type"])
                    resp = message_execute(j)
                    if resp != None:
                        resp_json = json.dumps(resp)
                        data_str = json.dumps({"message" : resp_json})
                        nonce = os.urandom(8)
                        b = aesccm.encrypt(nonce, bytes(data_str, 'utf-8'), None)
                        data_str = json.dumps({"nonce": base64.b64encode(nonce).decode(), "data" : base64.b64encode(b).decode()})
                        conn.send(bytes(data_str, 'utf-8'))
            
        except SocketError:
            pass

# repo lifecycle
while True:
    newsocket, fromaddr = bindsocket.accept()
    conn = context.wrap_socket(newsocket, server_side=True)
    start_new_thread(repo_thread, (conn,))