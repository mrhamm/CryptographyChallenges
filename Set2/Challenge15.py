import sys, os
sys.path.append(os.path.abspath('../Set1'))
import Set1Library as S1
import Set2Library as S2
import codecs

#tests the padding check -- to be used in set 3
valid = b"ICE ICE BABY\x04\x04\x04\x04"
invalid1 = b"ICE ICE BABY\x05\x05\x05\x05"
invalid2 = b"ICE ICE BABY\x01\x02\x03\x04"

print(S2.check_padding(valid))
print(S2.check_padding(invalid1))
print(S2.check_padding(invalid2))
