import Set2Library as S2

string = b"YELLOW SUBMARINE"
padded = S2.PKCS7_Pad(string,20)

print(padded)