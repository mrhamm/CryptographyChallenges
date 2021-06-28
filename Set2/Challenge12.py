import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
import Set2Library as S2
import codecs

message = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"\
b"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"\
b"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"\
b"YnkK"

Oracle = S2.ECB_Oracle(16,0)
message = codecs.decode(message,'base64')
#print(message)

#first we find the keysize
predicted_block_size = S2.predict_block_size(Oracle,message)
print(predicted_block_size)
#then, given that we are able to prepend something to the unknown message, we should be able to deduce the message
cracked_message = S2.force_decrypt_ECB(message,Oracle,predicted_block_size,0)
print(cracked_message)


