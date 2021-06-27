import Set1Library as S1
import codecs

file = open('Challenge8Txt.txt','r')
Lines = file.readlines()

results = []
for i in range(len(Lines)):
    line = codecs.decode(Lines[i][0:-1],'hex')
    if S1.is_ECB(line):
        results = results+[i]

print(results)