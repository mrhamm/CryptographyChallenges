import Set1Library as S1
import codecs

file = open('Challenge6Txt.txt','r')

Lines = file.readlines()
string = b""
for line in Lines:
    string = string  + bytes(line[0:-1],encoding="utf-8")


string = codecs.decode(string,"base64")
keys = S1.possible_key_sizes(string,40)
keysize = int(keys[0][1])
results = S1.repeated_XOR_decrypt(string,keysize) 

result = S1.single_byte_XOR(results[0],b' ')
print(result)
