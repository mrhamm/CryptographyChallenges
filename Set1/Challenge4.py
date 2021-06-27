import Set1Library as S1
import codecs
from numpy import argmax

file = open('Challenge4Txt.txt','r')
Lines = file.readlines()

scores = []
results = []
for j in range(len(Lines)):
    line = Lines[j][0:-1]
    if len(line)%2 != 0:
        line = '0'+line
    line = codecs.decode(line,'hex')
    result = S1.detect_single_byte_XOR(line)
    scores = scores + [result[1]]
    results = results +[result[0]]

index = argmax(scores)
print(S1.single_byte_XOR(results[index],b' '))
