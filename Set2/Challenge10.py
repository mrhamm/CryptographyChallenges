import Set2Library as S2
import codecs
from Crypto.Cipher import AES


file = open("Challenge10Txt.txt","r")
Lines = file.readlines()
string = b""
for line in Lines:
    line = bytes(line[0:-1],encoding="utf-8")
    string = string + line
string = codecs.decode(string,'base64')  

#this tests if decryption works based on cryptopals file
key = b"YELLOW SUBMARINE"
iv = b"\x00"*16
message = S2.AES_CBC_Decrypt(string,key,iv)
#should be supercalifragilisticexialidocious 
print(message)

#this checks encryption method versus built in decryption
message = b"AES is based on a design principle known as a substitution permutation network It is efficient in both software and hardware"
encrypted_message = S2.AES_CBC_Encrypt(message,key,iv)
cipher = AES.new(key,AES.MODE_CBC,iv)
test = cipher.decrypt(encrypted_message)
#test should be message
print(test)