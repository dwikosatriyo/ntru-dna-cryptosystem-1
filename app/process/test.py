from pydoc import plain
import sys, os
import time
# sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntruEnc')))
sys.path.append(os.path.abspath(os.path.join('kode','app','process','cryptography','ntru3Enc')))
sys.path.append(os.path.abspath(os.path.join('kode','app','process','cryptography','elgamalEnc')))
sys.path.append(os.path.abspath(os.path.join('kode','app','process','cryptography','eccEnc')))
sys.path.append(os.path.abspath(os.path.join('kode','app','process','steganography','subtitutionDNA')))
# print(sys.path)
import rsa, elgamal, eccrypt, ecdsa, subtitutionDNA, ntruStandart
from fractions import Fraction as frac
# import fracModulo,poly
from operator import add
from operator import neg



def encNtruTime (plaintext, securityLevel):
    times = []
    keySize = securityLevel
    
    start_time = time.time_ns()
    param = ntruStandart.NTRUParams(keySize,'speed')
    key = ntruStandart.NTRUKey(param)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    enc = ntruStandart.NTRUEncrypt(key.ring, key.h, plaintext)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    m = ntruStandart.NTRUDecrypt(key, *enc)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)
    return times

def encECCTime (message, securityLevel):
    if securityLevel == 112:
        keySize = 224
    elif securityLevel ==128:
        keySize = 256
    elif securityLevel == 192:
        keySize = 384
    elif securityLevel == 256:
        keySize = 521

    # print(message)
    times = []

    start_time = time.time_ns()

    key = ecdsa.keypair(keySize)

    times.append((time.time_ns() - start_time)/ (10 ** 9))
    #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
    # print(key[0])
    start_time = time.time_ns()

    cipher = eccrypt.encrypt(message, key[0])

    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # print(cipher[1])
    start_time = time.time_ns()

    plaintext = eccrypt.decrypt(cipher[0], cipher[1], key[1])

    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # result=[]
    # result.append(key[0][1])
    # result.append(key[1][1])
    # result.append(message)
    # result.append(cipher[0])
    # result.append(cipher[1])
    # result.append(plaintext)
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)
    return times
def encElGamalTime(message, securityLevel):
    if securityLevel == 112:
        keySize = 224
    elif securityLevel ==128:
        keySize = 256
    elif securityLevel == 192:
        keySize = 384
    elif securityLevel == 256:
        keySize = 512
    times = []

    start_time = time.time_ns()
    # print(keySize)
    key = elgamal.generate_keys(keySize,32)

    times.append((time.time_ns() - start_time)/ (10 ** 9))
    #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
    start_time = time.time_ns()

    cipher = elgamal.encrypt(key["publicKey"], message)

    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    plaintext = elgamal.decrypt(key["privateKey"], cipher)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    # result=[]
    # publicKey = "p ="+str(key["publicKey"].p)+"; g = "+str(key["publicKey"].g)+"; h = "+str(key["publicKey"].h)
    # privateKey = "p ="+str(key["privateKey"].p)+"; g = "+str(key["privateKey"].g)+"; x = "+str(key["privateKey"].x)
    # result.append(publicKey)
    # result.append(privateKey)
    # result.append(message)
    # result.append(cipher)
    # result.append(plaintext)
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)

    return times
def encRSATime(message, securityLevel):
    if securityLevel == 112:
        keySize = 2048
    elif securityLevel ==128:
        keySize = 3072
    elif securityLevel == 192:
        keySize = 7680
    elif securityLevel == 256:
        keySize = 15360
    times = []
    start_time = time.time_ns()
    (bob_pub, bob_priv) = rsa.newkeys(keySize)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    message = message.encode('utf8')

    start_time = time.time_ns()
    crypto = rsa.encrypt(message, bob_pub)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    message = rsa.decrypt(crypto, bob_priv)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    # message = message.decode('utf8')
    # result=[]
    # result.append(bob_pub)
    # result.append(bob_priv)
    # result.append(message)
    # result.append(crypto)
    # result.append(message)
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)

    return times




# def encNtruTimesResult(plaintext, securityLevel):
#     times = []
#     keySize = securityLevel

#     start_time = time.time_ns()
#     param = ntruStandart.NTRUParams(keySize,'speed')
#     key = ntruStandart.NTRUKey(param)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))

#     start_time = time.time_ns()
#     enc = ntruStandart.NTRUEncrypt(key.ring, key.h, plaintext)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))

#     start_time = time.time_ns()
#     m = ntruStandart.NTRUDecrypt(key, *enc)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))
#     totaltimes = 0
#     for i in times :
#         totaltimes = totaltimes+i
#     times.append(totaltimes)
#     return times, result

# def encECCTime (message, securityLevel):
#     if securityLevel == 112:
#         keySize = 224
#     elif securityLevel ==128:
#         keySize = 256
#     elif securityLevel == 192:
#         keySize = 384
#     elif securityLevel == 256:
#         keySize = 521

#     # print(message)
#     times = []

#     start_time = time.time_ns()

#     key = ecdsa.keypair(keySize)

#     times.append((time.time_ns() - start_time)/ (10 ** 9))
#     #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
#     # print(key[0])
#     start_time = time.time_ns()

#     cipher = eccrypt.encrypt(message, key[0])

#     times.append((time.time_ns() - start_time)/ (10 ** 9))
#     # print(cipher[1])
#     start_time = time.time_ns()

#     plaintext = eccrypt.decrypt(cipher[0], cipher[1], key[1])

#     times.append((time.time_ns() - start_time)/ (10 ** 9))
#     # result=[]
#     # result.append(key[0][1])
#     # result.append(key[1][1])
#     # result.append(message)
#     # result.append(cipher[0])
#     # result.append(cipher[1])
#     # result.append(plaintext)
#     totaltimes = 0
#     for i in times :
#         totaltimes = totaltimes+i
#     times.append(totaltimes)
#     return times
# def encElGamalTime(message, securityLevel):
#     if securityLevel == 112:
#         keySize = 224
#     elif securityLevel ==128:
#         keySize = 256
#     elif securityLevel == 192:
#         keySize = 384
#     elif securityLevel == 256:
#         keySize = 512
#     times = []

#     start_time = time.time_ns()
#     # print(keySize)
#     key = elgamal.generate_keys(keySize,32)

#     times.append((time.time_ns() - start_time)/ (10 ** 9))
#     #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
#     start_time = time.time_ns()

#     cipher = elgamal.encrypt(key["publicKey"], message)

#     times.append((time.time_ns() - start_time)/ (10 ** 9))

#     start_time = time.time_ns()
#     plaintext = elgamal.decrypt(key["privateKey"], cipher)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))

#     # result=[]
#     # publicKey = "p ="+str(key["publicKey"].p)+"; g = "+str(key["publicKey"].g)+"; h = "+str(key["publicKey"].h)
#     # privateKey = "p ="+str(key["privateKey"].p)+"; g = "+str(key["privateKey"].g)+"; x = "+str(key["privateKey"].x)
#     # result.append(publicKey)
#     # result.append(privateKey)
#     # result.append(message)
#     # result.append(cipher)
#     # result.append(plaintext)
#     totaltimes = 0
#     for i in times :
#         totaltimes = totaltimes+i
#     times.append(totaltimes)

#     return times
# def encRSATime(message, securityLevel):
#     if securityLevel == 112:
#         keySize = 2048
#     elif securityLevel ==128:
#         keySize = 3072
#     elif securityLevel == 192:
#         keySize = 7680
#     elif securityLevel == 256:
#         keySize = 15360
#     times = []
#     start_time = time.time_ns()
#     (bob_pub, bob_priv) = rsa.newkeys(keySize)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))
#     message = message.encode('utf8')

#     start_time = time.time_ns()
#     crypto = rsa.encrypt(message, bob_pub)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))

#     start_time = time.time_ns()
#     message = rsa.decrypt(crypto, bob_priv)
#     times.append((time.time_ns() - start_time)/ (10 ** 9))

#     # message = message.decode('utf8')
#     # result=[]
#     # result.append(bob_pub)
#     # result.append(bob_priv)
#     # result.append(message)
#     # result.append(crypto)
#     # result.append(message)
#     totaltimes = 0
#     for i in times :
#         totaltimes = totaltimes+i
#     times.append(totaltimes)

#     return times