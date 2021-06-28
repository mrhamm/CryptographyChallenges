# CryptoPals Challenge Repository

This is a repository of my solutions to the Cryptopals.com encryption challenges.  I am 
solving these challenges in Python3 for my own education and recreation.  

**This repository is not a replacement for completing the challenges on your own in a way that you understand, it is meant for discussion and inspiration.**

I will include each challenge set as I complete it.  Each set folder has its own library (accordingly labelled) which contains the main cryptographic functions required to solve the challenges.  The challenge texts are included, and each challenge is solved in its own python file.  

## Challenge Sets & Topics
**Set 1:** This set contains contains methods to "crack" basic XOR encryption methods, including single byte XOR and repeated key XOR encryption.  If such a XOR encrypted message contains easily identifiable english, the encryption key can easily be deduced by brute force guessing.  The final two challenges of the set introduce AES ECB mode block encryption, and demonstrates a method for detecting the ECB mode encryption method.  

**Set 2:** This set contains basic block-cipher attacks.  This includes implementing both ECB and CBC block-cipher encryption as well as several attacks.  Given an ECB encryption oracle for an unknown message, the ECB cipher can be cracked to deduce the message.  ECB is susceptible to 'cut-and-paste' attacks given an oracle that produces a cipher from an input text.  Lastly, CBC is susceptible to bit-flipping.  This set shows how both cut-and-paste attacks and bit-flipping attacks can maliciously insert admin privileges into encrypted ciphertext.  