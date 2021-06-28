import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
import Set2Library as S2
import codecs

#we will have a message sandwiched between these, but it will remove ; and = from the message
s1 = b"comment1=cooking%20MCs;userdata="
s2 = b";comment2=%20like%20a%20pound%20of%20bacon"

#we make a dummy message
message = b'A'*16
#we make an admin block to include
target = S2.PKCS7_Pad(b';admin=true;',16)
#we XOR the message and this target
bit_mix = S1.byte_string_XOR(message,target)

#the oracle then encrypts the intended message
Oracle = S2.CBC_Oracle(16)
ciphertext = Oracle.encrypt_comment(message,s1,s2)
print('Intended')
print(Oracle.decrypt(ciphertext))

#you intercept the message, and XOR the block before your message with the bit_mix from earlier
flipped_block = S1.byte_string_XOR(ciphertext[16:32],bit_mix)
#you then replace that block with the newly XORd block
flipped_text = ciphertext[0:16] + flipped_block + ciphertext[32:]
#when the receiver decrypts the new ciphertext, it finds admin permissions
new_msg = Oracle.decrypt(flipped_text)
print('Bit-Flipped')
print(new_msg)