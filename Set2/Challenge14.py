import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
import Set2Library as S2
import codecs

message = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"\
b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"\
b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"\
b"YnkK"

Oracle = S2.ECB_Oracle(16,5)
message = codecs.decode(message,'base64')

#brute force decrypts and unknown message assuming access to the encryption oracle
prefix_size,block_size = S2.predict_prefix_size(Oracle,message)
cracked_msg = S2.force_decrypt_ECB(message,Oracle,block_size,prefix_size)
print(cracked_msg)

