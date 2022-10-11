from pydoc import plain
import sys, os
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntruEnc')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','elgamalEnc')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','eccEnc')))
sys.path.append(os.path.abspath(os.path.join('app','process','steganography','subtitutionDNA')))
import rsa, elgamal, eccrypt, ecdsa, subtitutionDNA
import ntru,fracModulo,poly
from fractions import Fraction as frac
from operator import add
from operator import neg

def encNtru (plaintext, N, p, q, f, g, d,  randPol):
    # print(plaintext)
    result=[]
    N = int(N)
    p = int(p)
    q = int(q)
    f = f.split()
    f = list(map(int, f))
    g = g.split()
    g = list(map(int, g))
    d = int(d)
    # plaintext = plaintext.encode('ascii')
    # print(randPol)
    msg_real=plaintext
    plaintext = list(plaintext)
    plaintext = [ord(character) for character in plaintext]
    plaintext = [str(int(bin(character)[2:])) for character in plaintext]
    plaintext = "".join(plaintext)
    msg = plaintext
    plaintext = [int(char) for char in plaintext]
    # M = [map(int,i) for i in plaintext]
    if plaintext[len(plaintext)-1] == 0:
        plaintext[len(plaintext)-1] = 2
    randPol = randPol.split()
    randPol = list(map(int, randPol))

    D=[0]*(N+1)
    D[0]=-1
    D[N]=1

    [gcd_f,s_f,t_f]=poly.extEuclidPoly(f,D)

    f_p=poly.modPoly(s_f,p)
    f_q=poly.modPoly(s_f,q)
    # print("F_p:",f_p)
    # print("F_q:",f_q)

    x=poly.multPoly(f_q,g)
    h=poly.reModulo(x,D,q)

    # print("\n====And finally h====")
    # print("f_q x g: ",x)
    # print("H (Bob's Public Key): ",h)

    # print("\n====Let's encrypt====")
    # msg=[1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1]
    # randPol=[-1,-1,1,1]

    # print("Alice's Message:\t",plaintext)
    # print("Random:\t\t\t",randPol)
    e_tilda=poly.addPoly(poly.multPoly(poly.multPoly([p],randPol),h),plaintext)
    e=poly.reModulo(e_tilda,D,q)

    # print("Encrypted message:\t",e)

    # print("\n====Let's decrypt====")

    tmp=poly.reModulo(poly.multPoly(f,e),D,q)
    centered=poly.cenPoly(tmp,q)
    m1=poly.multPoly(f_p,centered)
    tmp=poly.reModulo(m1,D,p)
    decrypt = poly.trim(tmp)
    # print(decrypt)
    if decrypt[len(decrypt)-1] == 2:
        decrypt[len(decrypt)-1] = 0
    decrypt_b = [str(int) for int in decrypt]
    decrypt_b = "".join(decrypt_b)
    # print(len(decrypt_b))
    # print(decrypt_b[:-(len(decrypt_b)%8)])
    # print(decrypt_b)
    decrypt_pltx_length = int(len(decrypt_b)/7)
    # print(decrypt_pltx_length)
    decrypt_pltx = []
    for i in range(decrypt_pltx_length):
        # print(decrypt_b[i*7:(i+1)*7])
        temp = int(decrypt_b[i*7:(i+1)*7], base =2)
        temp = temp.to_bytes((temp.bit_length() + 7) // 8, 'big').decode()
        decrypt_pltx.append(temp)
    decrypt_pltx = "".join(decrypt_pltx)
        # decrypt_pltx = int(decrypt_pltx, base =2)
        # decrypt_pltx = decrypt_pltx.to_bytes((decrypt_pltx.bit_length() + 7) // 8, 'big').decode()
    # binary_int = int(decrypt, 2)
    # #get the byte number
    # byte_number = binary_int.bit_length() + 7 // 8
    # binary_array = binary_int.to_bytes(byte_number, "big")
    # print(byte_number)
    # ascii_text = binary_array.decode()

    result=[]
    result.append(f)
    result.append(g)
    result.append(f_p)
    result.append(f_q)
    result.append(x)
    result.append(h)
    result.append(msg_real)
    result.append(msg)
    result.append(randPol)
    result.append(e)
    result.append(decrypt)
    result.append(decrypt_pltx)

    # D=[0]*(N+1)
    # D[0]=-1
    # D[N]=1
    # [gcd_f,s_f,t_f]=poly.extEuclidPoly(f,D)
    # f_p=poly.modPoly(s_f,p)
    # f_q=poly.modPoly(s_f,q)
    # x=poly.multPoly(f_q,g)
    # h=poly.reModulo(x,D,q)
    # # plaintext=[1,0,1,0,1,1,1]
    # e_tilda=poly.addPoly(poly.multPoly(poly.multPoly([p],randPol),h),plaintext)
    # encrypt=poly.reModulo(e_tilda,D,q)
    # # print(e)
    # tmp=poly.reModulo(poly.multPoly(f,encrypt),D,q)
    # centered=poly.cenPoly(tmp,q)
    # m1=poly.multPoly(f_p,centered)
    # tmp=poly.reModulo(m1,D,p)
    # decrypt = poly.trim(tmp)
    # print(decrypt)

    
    # Bob = ntru.Ntru(N,p,q)
    # Bob.genPublicKey(f,g,d)
    # publicKey = Bob.getPublicKey()

    # Alice=ntru.Ntru(N,p,q)
    # Alice.setPublicKey(publicKey)
    # encrypt_msg= Alice.encrypt(plaintext,randPol)
    # decrypt_msg = Bob.decrypt(encrypt_msg)
    # print (decrypt_msg,flush=True)
    # decrypt_msg = ''.join(chr(i) for i in decrypt_msg)
    # print(publicKey,encrypt_msg,decrypt_msg)
    # return publicKey,encrypt_msg,decrypt_msg
    return result

def encECC (message, keySize):
    # print(message)
    key = ecdsa.keypair(keySize)
    #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
    # print(key[0])
    cipher = eccrypt.encrypt(message, key[0])
    # print(cipher[1])

    plaintext = eccrypt.decrypt(cipher[0], cipher[1], key[1])
    result=[]
    result.append(key[0][1])
    result.append(key[1][1])
    result.append(message)
    result.append(cipher[0])
    result.append(cipher[1])
    result.append(plaintext)
    return result
def encElGamal(message, keySize):
        
    key = elgamal.generate_keys(keySize)
    #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
    cipher = elgamal.encrypt(key["publicKey"], message)

    plaintext = elgamal.decrypt(key["privateKey"], cipher)
    result=[]
    publicKey = "p ="+str(key["publicKey"].p)+"; g = "+str(key["publicKey"].g)+"; h = "+str(key["publicKey"].h)
    privateKey = "p ="+str(key["privateKey"].p)+"; g = "+str(key["privateKey"].g)+"; x = "+str(key["privateKey"].x)
    result.append(publicKey)
    result.append(privateKey)
    result.append(message)
    result.append(cipher)
    result.append(plaintext)
    return result
def encRSA(message, keySize):
    (bob_pub, bob_priv) = rsa.newkeys(keySize)
    message = message.encode('utf8')
    crypto = rsa.encrypt(message, bob_pub)

    message = rsa.decrypt(crypto, bob_priv)
    message = message.decode('utf8')
    result=[]
    result.append(bob_pub)
    result.append(bob_priv)
    result.append(message)
    result.append(crypto)
    result.append(message)
    return result