# Description of this example is provided in NTRU.md

from ntru import *

#Bob
print("Bob Will Generate his Public Key using Parameters")
print("N=7,p=29 and q=491531")
Bob=Ntru(7,29,491531)
f=[1,1,-1,0,-1,1]
g=[-1,0,1,1,0,0,-1]
d=2
print("f(x)= ",f)
print("g(x)= ",g)
print("d   = ",d)
Bob.genPublicKey(f,g,2)
pub_key=Bob.getPublicKey()
print("Public Key Generated by Bob: ",pub_key)
print("-------------------------------------------------")
#Alice
Alice=Ntru(7,29,491531)
Alice.setPublicKey(pub_key)
msg=[1,0,1,0,1,1,1]
print("Alice's Original Message   : ",msg)
ranPol=[-1,-1,1,1]
print("Alice's Random Polynomial  : ",ranPol)
encrypt_msg=Alice.encrypt(msg,ranPol)
print("Encrypted Message          : ", encrypt_msg)
print("-------------------------------------------------")
#BOB
print("Bob decrypts message sent to him")
print("Decrypted Message          : ", Bob.decrypt(encrypt_msg))
