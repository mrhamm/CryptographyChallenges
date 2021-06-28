import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
import Set2Library as S2
import codecs
#insert at least 2 blocks of repeated characters to check for ECB
message = b"A"*48
key = S2.random_key(16)
encrypted = S2.AES_Oracle(message,key)
check = S1.is_ECB(encrypted,16)
print("Is ECB? " + str(check))
