import json
import sys
import getopt
import PyKCS11
import binascii
import base64
import ssl
import socket
import secrets
import os
import hashlib as hasher
import os.path
import copy
import subprocess, shutil
import getpass
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key, Encoding
from cryptography.hazmat.primitives.hashes import SHA256, SHA1
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from os import scandir, path, listdir, remove, _exists
from os.path import isfile, join
# Functions to store data on zip in an encrypted way and the reverse
from encrypt_folder import zzip, unzip

# get connection for server
def ssl_connect():
    server_hostname = 'localhost'
    server_ca = 'sioCACertificate.pem'
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=server_ca)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return context.wrap_socket(s, server_side=False, server_hostname=server_hostname)

# connect to repo
repo_addr = '127.0.0.1'
repo_port = 8081
repo_conn = ssl_connect() 
repo_conn.connect((repo_addr, repo_port))

# receive all message from socket
def recvall(sock):
    BUFF_SIZE = 4096
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            break
    return data

# # # # # # # # # # # 
# INITIAL MESSAGES  #
# # # # # # # # # # #

# save key for AESCCM 
keys = {}


# check if smartcard reader is inserted
def verify_inserted_smartCard():
    while True:
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        if len(slots) != 0:
            return slots, pkcs11

# read the session, user certificate, private key, username and serial_number
def readCC():
    while True:
        try:

            # check if smartcard reader is inserted
            slots, pkcs11 = verify_inserted_smartCard()

            for slot in slots:
                pass

            # Filter attributes
            all_attr = [e for e in list(PyKCS11.CKA.keys()) if isinstance(e, int)]
            session = pkcs11.openSession(slot)

            # Store username and the serial number
            user = ""
            serial_number = ""

            for obj in session.findObjects():
                # Get object attributes
                attr = session.getAttributeValue(obj, all_attr)
                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
                if attr['CKA_CERTIFICATE_TYPE'] != None:
                    # Store certificate
                    cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), default_backend())
                    try:
                        # username = given name + surname
                        if user == "":
                            user += cert.subject.get_attributes_for_oid(NameOID.GIVEN_NAME)[0].value + " " + cert.subject.get_attributes_for_oid(NameOID.SURNAME)[0].value 
                        if serial_number == "":
                            serial_number += cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
                    except:
                        pass
                    break
            # get certificate private key for message sign
            private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            return session, cert, private_key, user, serial_number
        except:
            pass

session, cert, private_key, username, serial_number = readCC()

# generate a totally random AESCCM
def generate_aes():
    key = AESCCM.generate_key(bit_length=128)
    aesccm = AESCCM(key)
    nonce = os.urandom(13)
    return aesccm, key, nonce

# load repository cert, get public key from it and cipher 'data'
def cipher_repo_public(data):
    f = open('repositoryCertificate.pem', 'rb')
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    pub_k = cert.public_key()
    ciphered_data = pub_k.encrypt(
        data,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphered_data

# signMessage and return the signature of it
def signMessage(message):
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
    signature = None
    # try to sign and wait for card if not inserted
    try:
        signature = bytes(session.sign(private_key, message, mechanism))
    except:
        # check if smartcard reader is inserted
        slots, pkcs11 = verify_inserted_smartCard()

        while True:
            try: 
                for slot in slots:
                    pass
                all_attr = list(PyKCS11.CKA.keys())
                # Filter attributes
                all_attr = [e for e in all_attr if isinstance(e, int)]
                session = pkcs11.openSession(slot)
                signature = bytes(session.sign(private_key, message, mechanism))
                break
            except:
                pass
    return signature

# encrypt message with aes and a random nonce
def message_cipher_aes(message):
    nonce = os.urandom(13)
    aesccm = AESCCM(keys['repository'])
    return aesccm.encrypt(nonce, bytes(message, 'utf-8'), None), nonce

# decrypt message with the stored key and a certain nonce
def message_decipher_aes(message, nonce):
    aesccm = AESCCM(keys['repository'])
    return aesccm.decrypt(nonce, message, None).decode()

# send AES key to the repo so that he can store it for later use with the client
def sendAES(data, key):
    repo_conn.send(bytes(json.dumps(data),"utf-8"))
    d = json.loads(recvall(repo_conn).decode("utf-8"))
    # for invalid otps
    if "response" in d.keys():
        return d
    return json.loads(AESCCM(key).decrypt(base64.b64decode(d['nonce']), base64.b64decode(d['data']), None)) 


# Switch AES with the repo and verify if otp is needed
def exchangeAES():
    cert_text = base64.b64encode(cert.public_bytes(Encoding.PEM)).decode()
    # send message for repository to check if an OTP is needed
    repo_conn.send(bytes(json.dumps({'type' : 'otp_needed'}),"utf-8"))
    d = json.loads(recvall(repo_conn).decode())
    otp = b"none"
    if d["response"] == "yes":
        otp = input("OTP: ")
        otp = bytes(otp, "utf-8")

    # generate AES and chiper key, nonce and otp with repo pub key
    repo_aesccm, key, nonce = generate_aes()
    ciphered_key = cipher_repo_public(key)
    ciphered_nonce = cipher_repo_public(nonce)
    ciphered_otp = cipher_repo_public(otp)

    # sign key and nonce
    print("Sign key to repo")
    signed_key = signMessage(ciphered_key)
    print("Sign nonce to repo")
    signed_nonce = signMessage(ciphered_nonce)

    data = {'type' : 'save_session_key', 'to' : 'repository', 'cert' : cert_text, 'signed_key' : base64.b64encode(signed_key).decode(), 'ciphered_key' : base64.b64encode(ciphered_key).decode(), 'signed_nonce' : base64.b64encode(signed_nonce).decode(), 'ciphered_nonce' : base64.b64encode(ciphered_nonce).decode(), 'ciphered_otp' : base64.b64encode(ciphered_otp).decode()}
    
    # send AES and check the response from the repository
    val = sendAES(data, key)
    if val['response'] == 'AES-CCM SAVED':
        print('[repository] : ', 'I\'ve saved your AES-CCM!')
        keys['repository'] = key
        return val['global_id']
    elif val['response'] == "INVALID OTP": 
        print('[repository] : ', 'The OTP you inserted was incorrect\nShutting down...')
        sys.exit(1)

# exchange AES with the repo
global_id = exchangeAES()
print('Session id:', global_id)
# set password for zip encryption
passw = getpass.getpass("Password for zip :")

# # # # # # # # # #
# VALIDATION CODE # 
# # # # # # # # # #

class AuctionInfo():
    # roots and user_roots for certificate chain validation
    roots = {}
    user_roots = {}

# cryptopuzzle method solver
def solve(difficulty, block_json):
    solution =  hash_function(json.dumps(block_json))
    while solution[:difficulty] != "1"*difficulty:
        block_json["Nonce"] += 1
        block_json["Timestamp"] = str(datetime.now())
        solution = hash_function(json.dumps(block_json))
    block_json["Solution"] = solution
    return block_json

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
        # print("Chain completed")
        return True
    if issuer in AuctionInfo.user_roots:
        return buildIssuers(chain, AuctionInfo.user_roots[issuer])
    if issuer in AuctionInfo.roots:
        return buildIssuers(chain, AuctionInfo.roots[issuer])
    print("Unable to create trust chain")
    return False

# validate a specific cert building its chain
def validate_cert(cert_block):
    if validateDate(cert_block.not_valid_before, cert_block.not_valid_after):
        AuctionInfo.user_roots[cert_block.subject] = cert_block
    for entry in scandir("./cc_certs/"):
        try:
            c = getCert(path.join("./cc_certs/",entry.name), "./cc_certs/" + str(entry.name))
            if c != None:
                subject = c.subject
                AuctionInfo.roots[subject] = c
        except:
            print("Cert error")
    return buildIssuers([], cert_block)

# validate block data
def validate_block(chain, index, manager_key, owner_key, cipher_fields):
        curr_block = chain[index]
        validation_str= "Block " + str(index) + " |"

        curr_block_block_dic = json.loads(curr_block[0])
        expected_puzzle_solution = (solve(curr_block_block_dic["Puzzle Difficulty"] , curr_block[1]))["Solution"]
        validation_str += "\n\t Expected Puzzle Solution: " + expected_puzzle_solution
        validation_str += "\n\t Puzzle Solution: " + curr_block_block_dic["Puzzle Solution"]
        # check if puzzle solution is equal to expexcted
        solution_is_equal = expected_puzzle_solution == curr_block_block_dic["Puzzle Solution"]

        if solution_is_equal:
            validation_str += "\n\t Correct Puzzle Solution"
        else:
            validation_str += "\n\t Incorrect Puzzle Solution"

        # initial block with the auction data
        if index == 0:
            cert_block = x509.load_pem_x509_certificate(base64.b64decode(curr_block_block_dic["Data"]["cert"]), backend=default_backend())
            val = validate_cert(cert_block)
            signature_ok = False
            if val:
                validation_str += "\n\t Valid Certificate"
                # verify signature
                if cert_block.public_key().verify(base64.b64decode(curr_block_block_dic["Data"]["signature"]), bytes(curr_block_block_dic["Data"]["creator"], 'utf-8'), padding.PKCS1v15(), SHA1()) == None:
                    validation_str += "\n\t Valid Signature"
                    signature_ok = True
            
            return solution_is_equal and signature_ok, validation_str
        
        # check chain order (given parent hash)
        previous_block = chain[index-1]

        parent_hash = curr_block_block_dic["Parent Hash"]
        real_parent_hash = hash_function(previous_block[0])
        hierarchical_link = parent_hash == real_parent_hash

        if hierarchical_link:
            validation_str += "\n\t Correct Hierarchical Link"

        # not the final block, the one with the keys used to encrypt data
        if owner_key == None:
            return solution_is_equal and hierarchical_link, validation_str

        # only for the last block        
        if index == len(chain)-1 : 
            cert_block = x509.load_pem_x509_certificate(base64.b64decode(curr_block_block_dic["Data"]["cert"]), backend=default_backend())
            val = validate_cert(cert_block)
            signature_ok = False
            if val:
                validation_str += "\n\t Valid Certificate"
                if cert_block.public_key().verify(base64.b64decode(curr_block_block_dic["Data"]["signature"]), base64.b64decode(curr_block_block_dic["Data"]["owner_key"]), padding.PKCS1v15(), SHA1()) == None:
                    validation_str += "\n\t Valid Signature"
                    signature_ok = True
            return solution_is_equal and hierarchical_link and signature_ok, validation_str
        
        
        manager_iv = base64.b64decode(curr_block_block_dic["Data"]["manager_nonce"])        
        user = curr_block_block_dic["Data"]["user"]
        bid = curr_block_block_dic["Data"]["bid"]

        if "user" in cipher_fields:
            # Decrypt th user using manager key
            user = manager_key.decrypt(manager_iv, base64.b64decode(curr_block_block_dic["Data"]["user"]), None)
            # Finally, decrypt with auciton owner key
            user = owner_key.decrypt(
                user,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode("utf-8")

        if "bid" in cipher_fields:
            # Decrypt th bid using manager key
            bid = manager_key.decrypt(manager_iv, base64.b64decode(bid), None)
            bid_for_sign = bid
            # Finally, decrypt with auciton owner key
            bid = owner_key.decrypt(
                bid,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode("utf-8")
        else:
            bid_for_sign = bytes(bid, 'utf-8')
        
        # decrypt AESCCM key and nonce used to encrypt cert
        cert_block = base64.b64decode(curr_block_block_dic["Data"]["user_certificate"])
        cert_key = manager_key.decrypt(manager_iv, base64.b64decode(curr_block_block_dic["Data"]["cert_key"]), None)
        cert_nonce = manager_key.decrypt(manager_iv, base64.b64decode(curr_block_block_dic["Data"]["cert_nonce"]), None)

        cert_key = owner_key.decrypt(
                cert_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        cert_nonce = owner_key.decrypt(
                cert_nonce,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        # load cert and verify signature
        cert_block = x509.load_pem_x509_certificate(AESCCM(cert_key).decrypt(cert_nonce, cert_block, None), backend=default_backend())
        val = validate_cert(cert_block)
        signature_ok = False
        if val:
            validation_str += "\n\t Valid Certificate"
            if cert_block.public_key().verify(base64.b64decode(curr_block_block_dic["Data"]["signature"]), bid_for_sign, padding.PKCS1v15(), SHA1()) == None:
                validation_str += "\n\t Valid Signature"
                signature_ok = True
        
        validation_str += "\n\t ----------\n\t User:"+user+"\n\t Bid:"+bid
        return solution_is_equal and hierarchical_link and signature_ok, validation_str, (user,bid)

def decrypt_receipts (deciphered_bids, manager_key, owner_key, cipher_fields, auction_id):
    
    receipts = []

    # decrypt zip from client
    if path.exists(serial_number + ".zip"):
        unzip(serial_number, passw)

    # get all receipts
    with open (serial_number + "_receipts", "r") as receipts_file:
        lines = receipts_file.readlines()
        for line in lines:
            curr_block_block_dic = json.loads(line)
            if int(curr_block_block_dic["Data"]["auction_id"]) == auction_id:
                # print(curr_block_block_dic)
                if "owner_key" in curr_block_block_dic["Data"].keys() or "creator" in curr_block_block_dic["Data"].keys():
                    receipts.append(curr_block_block_dic)
                
                else:
                    manager_iv = base64.b64decode(curr_block_block_dic["Data"]["manager_nonce"])
                    # print(manager_iv)
                    user = curr_block_block_dic["Data"]["user"]
                    if "user" in cipher_fields:
                        # Decrypt th user using manager key
                        user = base64.b64decode(curr_block_block_dic["Data"]["user"])
                        user = manager_key.decrypt(manager_iv, user, None)
                        # Finally, decrypt with auciton owner key
                        user = owner_key.decrypt(
                            user,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        user = user.decode("utf-8")

                    bid = curr_block_block_dic["Data"]["bid"]

                    if "bid" in cipher_fields:
                        bid = base64.b64decode(bid)
                        # Decrypt th bid using manager key
                        bid = manager_key.decrypt(manager_iv, bid, None)
                        # Finally, decrypt with auciton owner key
                        bid = owner_key.decrypt(
                            bid,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        bid = bid.decode("utf-8")

                    curr_block_block_dic["Data"]["user"] = user
                    curr_block_block_dic["Data"]["bid"] = bid

                    receipts.append(curr_block_block_dic)

    zzip(serial_number, passw)

    flag = True
    for r in receipts:
        flag = flag and (r in deciphered_bids)

    return flag

def validate_chain(chain):
    # get last block (contains the keys)
    last_block = chain[len(chain)-1]
    # get first block (ciphered fields)
    first_block = chain[0]

    if "owner_key" in last_block[1]["Data"]:
        manager_key = base64.b64decode(last_block[1]["Data"]["manager_key"])
        owner_key = load_pem_private_key(base64.b64decode(last_block[1]["Data"]["owner_key"]), None, default_backend())
        cipher_fields = first_block[1]["Data"]["anonymous_fields"]
        auction_id = first_block[1]["Data"]["auction_id"]

    flag = True
    deciphered_bids = []
    for i in range(len(chain)):
        if "owner_key" in last_block[1]["Data"]:
            validation = validate_block(chain,i, AESCCM(manager_key), owner_key, cipher_fields)
            if i != 0  and i != len(chain)-1:
                block = copy.copy(chain[i][1])
                if len(validation) > 2:
                    block["Data"]["user"] = validation[2][0]
                    block["Data"]["bid"] = validation[2][1]
                    deciphered_bids.append(block)
            else:
                deciphered_bids.append(copy.copy(chain[i][1]))
        else:
            validation = validate_block(chain,i,None, None, None)
        flag = flag and validation[0]
        print(validation[1])

    # produce decrypted chain
    if "owner_key" in last_block[1]["Data"]:
        all_receipts_inside = decrypt_receipts(deciphered_bids, AESCCM(manager_key), owner_key, cipher_fields,auction_id)
        if all_receipts_inside:
            print("All your receipts are inside the auctions chain!")

    print("Valid Chain? ", flag)
    if len(deciphered_bids) > 2:
        bid_values = [ int(b["Data"]["bid"]) for b in deciphered_bids[1:-1]]  
        i = bid_values.index(max(bid_values))
        b = deciphered_bids[1+i]

        print("Winner is \"" +b["Data"]["user"] +"\" paying " + b["Data"]["bid"] +"€ !")
    else:
        if len(deciphered_bids) == 0:
            print("This auction is still encrypted. Waiting for owners key....")
        else:
            print("There were no bids!")
    return flag

# get hash from data
def hash_function(data):
    sha = hasher.sha256()
    sha.update(data.encode('utf-8'))
    return sha.hexdigest()

# # # # # # # # #
# AUCTION  CODE # 
# # # # # # # # # 

# print menu
def menu():
    print("\n["+username+"]")
    print("1) CREATE AUCTION")
    print("2) END AUCTION")
    print("3) LIST OPEN/CLOSED AUCTIONS")
    print("4) SEND BID")
    print("5) SEND AUCTION PRIVATE KEY")
    print("6) VERIFY AUCTION")
    print("0) EXIT")

# get auction create data
def auction_create_data(data):
    data['type'] = 'auction_create'
    auction_name = input("Auction name? ")
    data['auction_name'] = auction_name
    print(" -> English Auction\n -> Blind Auction\n -> Single Bid")
    while True:
        auction_type = input("Auction type? ")
        auction_type = auction_type.replace(' ','_').lower()
        if os.path.isfile(auction_type +".py"):
            break
        else:
            print("No auction from that type")
    data['auction_type'] = auction_type
    auction_description = input("Auction description? ")
    data['auction_description'] = auction_description
    auction_difficulty = int(input("Default difficulty? "))
    data['auction_difficulty'] = auction_difficulty
    print(" -> Log Style")
    while True:
        auction_dif_func = input("Modification function? ")
        auction_dif_func = auction_dif_func.replace(' ','_').lower()
        if os.path.isfile(auction_dif_func +".py"):
            break
        else:
            print("Error, no file")
    with open(auction_dif_func + ".py", "r") as myfile:
        data['function'] = myfile.read()
    auction_anonymous_fields = input("Anonymous fields (user, bid)? ")
    data['auction_anonymous_fields'] = auction_anonymous_fields
    time = int(input("Auction time? (seconds) "))
    data['timer'] = time
    data['from'] = serial_number
    with open(auction_type + ".py", "r") as myfile:
        data['validation'] = myfile.read()

    # generate creator's auctions key
    private_creator_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    public_creator_key = private_creator_key.public_key()
    
    # encode public key in pem format
    pem = public_creator_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    data['auction_key'] = base64.b64encode(pem).decode()
    cert_bytes = cert.public_bytes(Encoding.PEM)
    data['cert'] = base64.b64encode(cert_bytes).decode()
    
    print("Signing first block")
    data['signature'] = base64.b64encode(signMessage(bytes(serial_number, 'utf-8'))).decode()

    return data, private_creator_key

# construct message
def construct_message(data):
    data_json = json.dumps(data)
    cipher_data, nonce = message_cipher_aes( data_json)
    message['data'] = base64.b64encode(cipher_data).decode()
    message['nonce'] = base64.b64encode(nonce).decode()
    return json.dumps(message)

# deconstruct message
def deconstruct_message(response):
    d = json.loads(response.decode())
    response = message_decipher_aes( base64.b64decode(d['data']), base64.b64decode(d['nonce']))
    response_json = json.loads(response)
    return json.loads(response_json['message'])

# verify repo signature
def verify_repo_signature(signature, message):
    f = open('repositoryCertificate.pem', 'rb')
    c = x509.load_pem_x509_certificate(f.read(), default_backend())
    pub_k = c.public_key()
    res = pub_k.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return res == None

# print menu and handle options
while True:
    # all messages have a 'header' with the id of the client
    message = {'from' : global_id}
    data = {}
    menu()
    op = input("Option? ")
    print()

    # close client code
    if op == "0":
        repo_conn.close()
        break

    # create auction
    if op == "1":
        # get data
        data, private_creator_key = auction_create_data(data)
        # construct message
        message_json = construct_message(data)
        repo_conn.send(bytes(message_json,"utf-8"))
        response = recvall(repo_conn)
        # deconstruct response
        response_json = deconstruct_message(response)
        
        # save private key as bytes
        pem = private_creator_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
         ) 

        if path.exists(serial_number + ".zip"):
            unzip(serial_number, passw)

        with open (serial_number + "_auction_keys" , "ab") as auction_keys_file:
            auction_keys_file.write(  str.encode(str(response_json['data'])) + b"\t" + pem +  b"\n\t\n\t")
            auction_keys_file.close()

        zzip(serial_number, passw)

        block_json =  json.loads(response_json["block"])
        block_json["Nonce"] = int(block_json["Nonce"])

        puzzle_difficulty = block_json["Data"]["puzzle_difficulty"]

        # solve block
        print("Calculation block...")
        solved_block = solve(puzzle_difficulty, block_json)
        print("Block solved")
        # print(solved_block)

        # enviar o block 
        msg = {'type' : 'solved_block', 'solution': json.dumps(solved_block)}
        # construct message
        message_json = construct_message(msg)
        repo_conn.send(bytes(message_json,"utf-8"))
        # get receipt
        response = recvall(repo_conn)
        # deconstruct response
        response_json = deconstruct_message(response)

        if verify_repo_signature(base64.b64decode(response_json["signature"]), bytes(response_json["solution"],'utf-8')) and solved_block["Solution"] == response_json["solution"]:
            print("[Valid receipt] Signature and puzzle solution validated.")
            if path.exists(serial_number + ".zip"):
                unzip(serial_number, passw)
            # save receipt to disk
            with open (serial_number + "_receipts", "a") as receipts_file:
                receipts_file.write( response_json["block"] + "\n")
                receipts_file.close()
            zzip(serial_number, passw)
        
    # send request to repo for showing open auctions where the current client is the owner
    if op == "2":
        # define message to be sent to the server
        data['type'] = 'listMyOpen'
        data['serial'] = serial_number
        # construct message
        message_json = construct_message(data)
        repo_conn.send(bytes(message_json,"utf-8"))
        # get response
        response = recvall(repo_conn)
        # deconstruct response
        d_json = deconstruct_message(response)

        if d_json['data'] != "":
            print(d_json['data'])
            auction = int(input('Auction? (number) '))
            data['type'] = 'endAuction'
            data['auction_id'] = auction
            # construct message
            message_json = construct_message(data)
            repo_conn.send(bytes(message_json,"utf-8"))
            print("Auction ended")
        else:
            print("You are not the owner of any open auction!")

    # send request to repo for showing all open and closed auctions
    if op == "3":
        data['type'] = 'listOpenClosed'
        # construct message
        message_json = construct_message(data)
        repo_conn.send(bytes(message_json,"utf-8"))
        response = recvall(repo_conn)
        # deconstruct response
        d_json = deconstruct_message(response)
        if d_json['data'] != "":
            print(d_json['data'])
            # ask for auction_id
            data = {}
            auction_id = input("Auction? ")
            data['type'] = 'get_auction'
            data['auction_id'] = int(auction_id)

            # construct message
            message_json = construct_message(data)
            repo_conn.send(bytes(message_json,"utf-8"))
            response = recvall(repo_conn)
            # deconstruct response
            d_json = deconstruct_message(response)
            # get some auctions info
            creator = d_json[0]["creator"]
            auction_name = d_json[0]["auction_name"]
            description = d_json[0]["description"]
            auction_id = d_json[0] ["auction_id"]
            anonymous_fields = d_json[0]["anonymous_fields"]
            print("\tCreator: " + creator)
            print("\tAuction Name: " + auction_name)
            print("\tAuction Id: " + str(auction_id))
            print("\tDescription: " + description)
            print("\tAnonymous Fields: " + anonymous_fields)

            counter = 1
            if len(d_json) > 1:
                print()
                for b in d_json:
                    if "user" in b.keys() and "bid" in b.keys():
                        print("\t---- Bloco " + str(counter) + " ----")
                        print("\tUser: " + b["user"])
                        print("\tBid: " + b["bid"] + " €")
                        counter += 1
        else:
            print("No auctions have been created!")
    

    # send bid to repository wich will be validated on manager
    if op == "4":
        # message to be sent to the repository
        data['type'] = 'listOpen'
        # construct message
        message_json = construct_message(data)
        repo_conn.send(bytes(message_json,"utf-8"))
        # get response
        response = recvall(repo_conn)
        # deconstruct response
        d_json = deconstruct_message(response)
        if d_json['data'] != "":
            # print open auctions
            print(d_json['data'])
            # ask for a bid to a specific auction
            auction = input("Auction? (number) ")
            bid = input("Bid? ")
            # get auctions info
            data = {"type" : "get_auction_info", "auction_id" : int(auction)}
            # construct message
            message_json = construct_message(data)
            repo_conn.send(bytes(message_json,"utf-8"))
            response = recvall(repo_conn)
            # deconstruct response
            r_json = deconstruct_message(response)
            # the client will have to encrypt the data with the auction key
            auction_key = r_json["creator_key"]
            cipher_fields = r_json["anonymous_fields"].split(",")
            # convert the key to a pem
            auction_key = load_pem_public_key(base64.b64decode(auction_key), backend=default_backend())
            
            # define user
            user = serial_number

            # cipher data
            if "user" in cipher_fields:
                user = auction_key.encrypt(
                bytes(user,'utf-8'),
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )
            
            if "bid" in cipher_fields:
                bid = auction_key.encrypt(
                bytes(bid, 'utf-8'),
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
                )
      
            # Encrypt certificate
            cert_bytes = cert.public_bytes(Encoding.PEM)
            key = AESCCM.generate_key(bit_length=128)
            aesccm = AESCCM(key)
            nonce = os.urandom(13)
            cert_cipher = aesccm.encrypt(nonce, cert_bytes, None)

            cipher_key = auction_key.encrypt(
                key,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
            )

            cipher_nonce = auction_key.encrypt(
                nonce,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                    )
            )

            if isinstance(user, bytes):
                user = base64.b64encode(user).decode()

            # sign the bid
            if  isinstance(bid, bytes):
                signature = signMessage(bid)
                data = {"from" : user, "type" : "bid", "auction_id" : auction, "cert" : base64.b64encode(cert_cipher).decode(), "cert_key" : base64.b64encode(cipher_key).decode(), "cert_nonce" : base64.b64encode(cipher_nonce).decode(), "signature" : base64.b64encode(signature).decode(), "bid" : base64.b64encode(bid).decode()}
            else:
                signature = signMessage(bytes(bid, 'utf-8'))
                data = {"from" : user, "type" : "bid", "auction_id" : auction, "cert" : base64.b64encode(cert_cipher).decode(), "cert_key" : base64.b64encode(cipher_key).decode(), "cert_nonce" : base64.b64encode(cipher_nonce).decode(), "signature" : base64.b64encode(signature).decode(), "bid" : base64.b64encode(bytes(bid, 'utf-8')).decode()}

            # construct message
            message_json = construct_message(data)
            repo_conn.send(bytes(message_json,"utf-8"))

            # get response from repo
            response = recvall(repo_conn)
            # deconstruct response
            response_json = deconstruct_message(response)

            if response_json["block"] != "Invalid Block":
                print("Valid bid")

                block_json =  json.loads(response_json["block"])
                block_json["Nonce"] = int(block_json["Nonce"])

                puzzle_difficulty = block_json["Data"]["puzzle_difficulty"] # int(response_json["difficulty"])

                # solve block
                print("Calculation block...")
                solved_block = solve(puzzle_difficulty, block_json)
                print("Block solved")

                # enviar o block 
                msg = {'type' : 'solved_block', 'solution': json.dumps(solved_block)}
                # construct message
                message_json = construct_message(msg)
                repo_conn.send(bytes(message_json,"utf-8"))

                # get receipt
                response = recvall(repo_conn)
                response_json = deconstruct_message(response)

                if response_json["block"] == None:
                    print("Auction has closed!")
                else:
                    if verify_repo_signature(base64.b64decode(response_json["signature"]),bytes(response_json["solution"],'utf-8')) and solved_block["Solution"] == response_json["solution"]:
                        print("[Valid receipt] Signature and puzzle solution validated.")
                        
                        if path.exists(serial_number + ".zip"):
                            unzip(serial_number, passw)
                        # save receipt to disk
                        with open (serial_number + "_receipts", "a") as receipts_file:
                            receipts_file.write( response_json["block"] + "\n")
                            receipts_file.close()
                        
                        zzip(serial_number, passw)
            else:
                print("Invalid Bid!")
        else:
            print("All auctions created are closed!")
    
    if op == "5":
        data['type'] = 'listMyClosed'
        data['serial'] = serial_number
        # construct message
        message_json = construct_message(data)
        repo_conn.send(bytes(message_json,"utf-8"))
        response = recvall(repo_conn)
        # deconstruct response
        d_json = deconstruct_message(response)
        if d_json['data'] != "":
            print(d_json['data'])
            auction = input('Auction? (number) ')
            data = {}
            data["type"] = "insert_last_block"

            # get auction key
            auction_keys = dict() 
            
            if path.exists(serial_number + ".zip"):
                unzip(serial_number, passw)

            with open (serial_number + "_auction_keys", "rb") as auction_keys_file:
                content = auction_keys_file.read()
                auctions = content.split(b"\n\t\n\t")
                # iterate over all auctions
                for a in auctions[:-1]:
                    a_id = (a.split(b"\t")[0]).decode("utf-8")
                    a_pw = a.split(b"\t")[1] 
                    auction_keys[a_id] = a_pw

            zzip(serial_number, passw)

            pem = auction_keys[str(auction)]

            cert_bytes = cert.public_bytes(Encoding.PEM)
            data['cert'] = base64.b64encode(cert_bytes).decode()
            print("Signing auction private key")
            data['signature'] = base64.b64encode(signMessage(pem)).decode()
            data["owner_key"] = base64.b64encode(pem).decode()
            data["auction_id"] = auction
            # construct message
            message_json = construct_message(data)
            repo_conn.send(bytes(message_json,"utf-8"))
            response = recvall(repo_conn)
            # deconstruct response
            response_json = deconstruct_message(response)

            if response_json["block"] != "Invalid Block":
                block_json =  json.loads(response_json["block"])
                block_json["Nonce"] = int(block_json["Nonce"])

                # print("------", block_json)
                puzzle_difficulty = (json.loads(response_json["block"])["Data"]["puzzle_difficulty"])# int(response_json["difficulty"])

                # solve block
                print("Calculation block...")
                solved_block = solve(puzzle_difficulty, block_json)
                print("Block solved")

                # enviar o block 
                msg = {'type' : 'solved_block', 'send_keys' : 'yes', 'solution': json.dumps(solved_block)}
                # construct message
                message_json = construct_message(msg)
                repo_conn.send(bytes(message_json,"utf-8"))
                # get receipt
                response = recvall(repo_conn)
                # deconstruct response
                response_json = deconstruct_message(response)
                # print(response_json)
                if response_json['block'] == None:
                    print("Auction has already been closed!")
                else:
                    if verify_repo_signature(base64.b64decode(response_json["signature"]), bytes(response_json["solution"],'utf-8')) and solved_block["Solution"] == response_json["solution"]:
                        print("[Valid receipt] Signature and puzzle solution validated.")
                        
                        if path.exists(serial_number + ".zip"):
                            unzip(serial_number, passw)
            
                        # save receipt to disk
                        with open (serial_number + "_receipts", "a") as receipts_file:
                            receipts_file.write( response_json["block"] + "\n")
                            receipts_file.close()

                        zzip(serial_number, passw)


                    # print("[VALID BID] Inserted block:", response_json["block"])
                
            else:
                print("Invalid Bid!")

        else:
            print("You are not the owner of any closed auction!")
        
    if op == "6":
        data['type'] = 'listOpenClosed'
        # construct message
        message_json = construct_message(data)
        repo_conn.send(bytes(message_json,"utf-8"))
        response = recvall(repo_conn)
        # deconstruct response
        d_json = deconstruct_message(response)
        if d_json['data'] != "":
            print(d_json['data'])
            auction = input('Auction? (number) ')
            data['type'] = 'requestChain'
            data['auction_id'] = auction
            # construct message
            message_json = construct_message(data)
            repo_conn.send(bytes(message_json,"utf-8"))
            # get chain from repository
            response = recvall(repo_conn)
            # deconstruct response
            response_json = deconstruct_message(response)
            blockchain = json.loads(response_json['blockchain'])
            if verify_repo_signature(base64.b64decode(response_json['digest_signature']), base64.b64decode(response_json['digest'])):
                print("Valid signature from repository on blockchain!")
            # print("My Block Chain:", blockchain)
            validate_chain(blockchain)
        else:
            print("No auctions even been created!")
