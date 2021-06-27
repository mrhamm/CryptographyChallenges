import codecs
from numpy import argmax, linspace, average
from math import ceil, floor
from Crypto.Cipher import AES


#converts hex encoding to base64 encoding, for challenge 1
def hex_to_base64(hexString):
    return codecs.encode(codecs.decode(hexString,'hex'),'base64')

#takes two byte strings of equal length and computes their XOR combination
def byte_string_XOR(s1,s2):
    s1 = codecs.encode(s1,'hex')
    s2 = codecs.encode(s2,'hex')
    XOR = hex(int(s1,16)^int(s2,16))[2:]
    if XOR[-1] == 'L':
        XOR = XOR[:-1]
    if len(XOR)%2!=0:
        XOR = '0'+XOR
    return bytes(codecs.decode(XOR,'hex'))

#takes a byte string and XORs it against a single character
def single_byte_XOR(string,character):
    if len(character)>1:
        print("Error, please only use 1 character for your XOR key")
    else:
        character = character*len(string)
        return byte_string_XOR(string,character)

#takes a byte string and gives it a score based on its similarity to english 
def English_Likeness_Score(string):
    List1 = [b'e',b'E',b't',b'T',b'a',b'A',b'o',b'O',b'i',b'I',b'n',b'N']#1st most common letters
    List2 = [b's',b'S',b'h',b'H',b'r',b'R',b'd',b'D',b'l',b'L',b'u',b'U']#2nd most common letters
    score = 0
    for i in range(len(string)):
        if string[i:i+1] in List1:
            score = score+2
        elif string[i:i+1] in List2:
            score = score+1
    return(score)

#if the string is encrypted by a single byte XOR, this will find the character 
#that it was XORd against, and decrypts the message
def detect_single_byte_XOR(byteString):
   scores = []
   chars = []
   for i in range(255):
       char = hex(i)[2:]
       if len(char)%2!=0:
           char = '0'+char
       char = codecs.decode(char,'hex')
       XOR = single_byte_XOR(byteString,char)
       score = English_Likeness_Score(XOR)
       scores = scores +[score]
       chars = chars + [char]
   index = argmax(scores)
   result = single_byte_XOR(byteString,chars[index])
   return (result,scores[index],chars[index])

#XOR encrypts a string with a repeating key
def repeating_key_XOR(string,key):
    repeats = int(floor(len(string)/len(key)))
    extras = len(string)%len(key)
    repeatedKey = key*repeats+key[0:extras]
    return byte_string_XOR(string,repeatedKey)

#computes the Hamming or Edit distance between two bytestrings of equal length
def Hamming_Distance(s1,s2):
    XOR = byte_string_XOR(s1,s2)
    binary = bin(int(codecs.encode(XOR,'hex'),16))
    distance = binary.count("1")
    return distance



#returns a list of key sizes for a repeated XOR encrypted string, max_size is the maximum tested key length
#ordered by likelihood of the key size being the encryption key length
#output is in the form of [*Normalized Average Hamming Distance*, key_size]
def possible_key_sizes(string,max_size):
    sizes = linspace(2,max_size,(max_size-1))
    scores = []
    for s in sizes:
        j=0
        distances = [] #for recording edit distances
        s1 = string[0:int(s)] #first block of encrypted text
        while (int(s)*(j+2))<=len(string):
            s2 = string[int(s)*(j+1):int(s)*(j+2)] #nth block of encrypted text
            distances = distances + [Hamming_Distance(s1,s2)] #finds the distance between
            j=j+1
        scores = scores + [[average(distances)/s,s]]#averages and normalizes by keysize, indexes with key size
    scores = sorted(scores,key=lambda x:x[0])
    return scores

#takes a repeated XOR encrypted string and its known keysize and 
#solves for the key and decrypts the message
def repeated_XOR_decrypt(string,keysize):
    #this chunks the text into blocks of length keysize
    blocks = []
    j=0
    while (keysize*(j+1))<=len(string):
        blocks = blocks + [string[j*keysize:(j+1)*keysize]]
        j=j+1

    #this transposes the text into keysize chunks, each chunk now corresponding to
    #a single byte XOR encrypted set of text
    transpose = [b"" for x in range(keysize)]
    for i in range(len(blocks)):
        block = blocks[i]
        for j in range(len(block)):
            transpose[j] = transpose[j] + block[j:j+1]

    key = b''#placeholder to build the encryption key
    for entry in transpose:
        block_key = detect_single_byte_XOR(entry)[-1]#finds the best guess for the single byte 
        key = key + block_key #adds that byte to the key
    decrypted_msg = repeating_key_XOR(string,key) #reverses the repeated key XOR with the newly constructed key
    return(decrypted_msg,key)

#looks for repeated blocks to detect a 128bit ECB cipher
def is_ECB(byte_string):
    #chunks the string into blocks of size 16
    blocks = []
    j = 0
    while (j+1)*16<=len(byte_string):
        blocks = blocks + [byte_string[j*16:(j+1)*16]]
        j=j+1

    repeats = len(blocks)-len(set(blocks))#counts how many blocks are repeated
    if repeats>0:
        return True #repeated blocks are a strong indicator of ECB encryption mode
    else:
        return False

#for Challenge 8
def reverse_AES_ECB(byte_string,key):
    #reverses ECB encryption given the key
    cipher = AES.new(key,AES.MODE_ECB)
    return(cipher.decrypt(byte_string))