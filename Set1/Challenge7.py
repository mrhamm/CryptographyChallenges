import Set1Library as S1
import codecs


file = open('Challenge7Txt.txt','r')
Lines = file.readlines()
string = b""
for line in Lines:
    line = bytes(line[0:-1],encoding="utf-8")
    string = string + line
    
string = codecs.decode(string,'base64')
key = b"YELLOW SUBMARINE"
text = S1.reverse_AES_ECB(bytes(string),key)

print(text)

