import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
import Set2Library as S2
import codecs

#If we have a valid profile that is encoded in ECB mode, we can insert admin access by cut-and-paste

profile = S2.profile_for(b'ben@email.com')
profile = S2.kv_converter(profile)

#the oracle encrypts the profile into a message, sends it to the receiver, and the receiver then decrypts it
Oracle = S2.ECB_Oracle(16,0)
intended_message = Oracle.encrypt(profile)
intended_profile = S2.parse_profile(intended_message,Oracle)
print("What they intended to receive")
print(intended_profile)

#we generate the admin privilege to include in a block
admin_block = S2.PKCS7_Pad(b'admin',16)
#then, making a dummy profile, we insert that block carefully so that it appears
#at the beginning of a ciphertext block
dummy_profile = S2.profile_for(b'ben'+b'A'*7+ admin_block +b'@email.com')
dummy_message = Oracle.encrypt(S2.kv_converter(dummy_profile))

#we then cut and paste the two messages together, adding the ciphered admin text
Cut_and_pasted_message = intended_message[0:-16]+dummy_message[16:32]
fake_profile = S2.parse_profile(Cut_and_pasted_message,Oracle)
#the server receives it and gets a fake profile with admin permission
print("What they actually receive")
print(fake_profile)