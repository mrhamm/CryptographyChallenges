from Crypto.Cipher import AES
import codecs
import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
from random import randint
from math import ceil

#applies padding up to 16 spaces
def PKCS7_Pad(byte_string,block_size):
    pads = block_size-len(byte_string)%block_size
    if pads < 16:
        HexPad = '0'+hex(pads)[2:]
    else:
        HexPad = hex(pads)[2:]
    Padding = codecs.decode(HexPad,'hex')*pads
    byte_string = byte_string+Padding
    return byte_string

#checks if padding format is valid
def check_padding(byte_string):
    char = byte_string[-1:]
    pads = int(codecs.encode(char,'hex'),16)
    if pads<16:
        valid = char*pads
        check = byte_string[-pads:]
        if check == valid:
            return True
        else:
            return False
    else:
        return True

#Decrypts in ECB mode with a given key
def AES_ECB_Decrypt(byte_string,key):
    cipher = AES.new(key,AES.MODE_ECB)
    return(cipher.decrypt(byte_string))

#Encrypts ECB mode with given key
def AES_ECB_Encrypt(byte_string,key):
    byte_string = PKCS7_Pad(byte_string,len(key))
    cipher = AES.new(key,AES.MODE_ECB)
    return(cipher.encrypt(byte_string))

#Encrypts CBC mode with given key and iv
def AES_CBC_Encrypt(byte_string,key,iv):
    cipher = AES.new(key,AES.MODE_ECB)
    byte_string = PKCS7_Pad(byte_string,len(key))
    block_size=len(key)
    previous = iv
    encrypted_byte_string = b''
    for i in range(0,len(byte_string),block_size):
        block = byte_string[i:i+block_size]
        XORD = S1.byte_string_XOR(block,previous)
        encrypted = cipher.encrypt(XORD)
        previous = encrypted
        encrypted_byte_string = encrypted_byte_string + previous
    return(encrypted_byte_string)

#decrypts CBC given key and iv
def AES_CBC_Decrypt(byte_string,key,iv):
    cipher= AES.new(key,AES.MODE_ECB)
    block_size = len(key)
    decrypted_byte_string = b''
    previous = iv
    for i in range(0,len(byte_string),block_size):
        block = byte_string[i:i+block_size]
        Decrypted = cipher.decrypt(block)
        UnXORD = S1.byte_string_XOR(Decrypted,previous)
        previous = block
        decrypted_byte_string = decrypted_byte_string + UnXORD
    return(decrypted_byte_string)

#generates random byte_string of given length (for generating keys later)
def random_key(key_length):
    return os.urandom(key_length)

#Produces a randomly padded and encrypted string in either ECB or CBC mode with 50/50 probability
#for challenge 11
def AES_Oracle(byte_string,key):
    left_pad = random_key(randint(5,11))
    right_pad = random_key(randint(5,11))
    byte_string = left_pad + byte_string + right_pad 
    if randint(0,2)==1:
        print("Oracle: ECB Mode")
        message = AES_ECB_Encrypt(byte_string,key)
    else:
        print("Oracle: CBC Mode")
        message = AES_CBC_Encrypt(byte_string,key,random_key(16))
    return message

#finds the block size of a block-cipher given the cipher oracle 
def predict_block_size(Oracle,string):
    msg_length = len(Oracle.encrypt(string))
    message2 = b"A"+string
    msg2_length = len(Oracle.encrypt(message2))
    while msg2_length==msg_length:
        message2 = b"A"+message2
        msg2_length = len(Oracle.encrypt(message2))
    predicted_block_size = msg2_length-msg_length
    return predicted_block_size

#counts number of repeating blocks in a ciphertext
def count_repeats(string,block_size):
    blocks = []
    j = 0
    while (j+1)*block_size<=len(string):
        blocks = blocks + [string[j*block_size:(j+1)*block_size]]
        j=j+1
    repeats = len(blocks)-len(set(blocks))
    return repeats

#finds both the block_size and prefix size of a block-cipher given its oracle
def predict_prefix_size(Oracle, string):
    block_size = predict_block_size(Oracle,string)
    repeats0 = count_repeats(Oracle.encrypt(string),block_size)
    string = b"A"*block_size*2 + string 
    repeats2 = count_repeats(Oracle.encrypt(string),block_size)
    count = 0
    while repeats2==repeats0:
        string = b"A"+string
        count = count+1
        repeats2 = count_repeats(Oracle.encrypt(string),block_size)
    modulus = block_size - count 
    message = Oracle.encrypt(string)
    count = 0
    while message[0:block_size]!=message[block_size:2*block_size]:
        message= message[block_size:]
        count=count+1
    prefix_length = (count-1)*block_size + modulus
    return (prefix_length,block_size)

#Assuming you can prepend something to an unknown string, this decrypts that string byte-by-byte
#Requires the block and prefix lengths
def force_decrypt_ECB(string,Oracle,block_size,prefix_size):
    input = b"A"*(block_size-1) +b"A"*(block_size-prefix_size) + string
    known = b"A"*(block_size-1)
    msg = b""
    for k in range(len(string)+block_size):
        check = Oracle.encrypt(b"A"*(block_size-prefix_size)+input[k:k+block_size])[block_size:]
        for i in range(256):
            if i<16:
                char = '0'+hex(i)[2:]
                test = known+codecs.decode(char,'hex')
            else:
                char = hex(i)[2:]
                test = known+codecs.decode(char,'hex')
            test = Oracle.encrypt(b"A"*(block_size-prefix_size)+test)[block_size:]
            if test == check:
                msg = msg + codecs.decode(char,'hex')
                known = known[1:]+codecs.decode(char,'hex')
    return msg

#key-value parsing, returns object
def kv_parser(string):
    obj = {}
    i=0
    left = 0
    while i<len(string)-1:
        if string[i:i+1] == b"=":
            key = str(string[left:i])
            left = i
            while string[i:i+1] !=b"&" and i<len(string)-1:
                i = i+1
            val = string[left+1:i]
            obj[key] = val
            left = i+1
        i=i+1
    return obj

#produces dummy-profile given an email with restrictions on characters
def profile_for(email_string):
    address = email_string.replace(b"=",b'')
    address = address.replace(b"&",b'')
    address = address.replace(b" ",b"")
    profile = {b'email': address,
    b'uid': b'10',
    b'role': b'user'}
    return profile

#converts object to kv string
def kv_converter(object):
    string = b''
    for key in object.keys():
        string = string + key + b'='+ object[key] + b'&'
    return string[0:-1]

#decrypts and parses an encrypted profile (challenge 13)
def parse_profile(message,Oracle):
    message = Oracle.decrypt(message)
    pads = int(codecs.encode(message[-1:],'hex'),16)
    if pads<=15:
        message = message[0:-(pads-1)]
    profile = kv_parser(message)
    return profile


#CBC oracle for challenge 16
class CBC_Oracle:
    def __init__(self,block_size):
        self.key = random_key(block_size)
        self.iv = random_key(block_size)

    def encrypt(self,string):
        return AES_CBC_Encrypt(string,self.key,self.iv)

    def decrypt(self,string):
        return AES_CBC_Decrypt(string,self.key,self.iv)

    def encrypt_comment(self,string,prefix,suffix):
        string = string.replace(b';',b'')
        string = string.replace(b'=',b'')
        return self.encrypt(prefix+string+suffix)

    def check_admin(self,string):
        string = self.decrypt(string)
        if b';admin=true;' in string:
            return True
        else:
            return False

#ECB oracle for challenges 11-14
class ECB_Oracle:
    def __init__(self,block_size,prefix_size):
        self.key = random_key(block_size)
        self.prefix_size = prefix_size
    def encrypt(self,string):
        string = random_key(self.prefix_size)+string
        return AES_ECB_Encrypt(string,self.key) 
    def decrypt(self,string):
        return AES_ECB_Decrypt(string,self.key)
    