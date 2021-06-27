import Set1Library as S1
import codecs

s1 = codecs.decode("1c0111001f010100061a024b53535009181c",'hex')
s2 = codecs.decode("686974207468652062756c6c277320657965",'hex')
print(s1)
print(s2)
result = S1.byte_string_XOR(s1,s2)
print(codecs.encode(result,'hex'))
print(result)



