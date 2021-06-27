import Set1Library as S1
import codecs


string = b"Burning 'em, if you ain't quick and nimble "\
    b"I go crazy when I hear a cymbal"

key = b"ICE"

result = S1.repeating_key_XOR(string,key)

print(codecs.encode(result,'hex'))


