import sys, os
import time
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography')))
sys.path.append(os.path.abspath(os.path.join('app','process','steganography')))
import test, subtitutionDNA, rsa, keyLib
from itertools import chain
from ntru3Enc import ntruStandart
from eccEnc import ecdsa, eccrypt
from elgamalEnc import elgamal

def binToStr(b):
    # bs = []
    # for i in range(int(len(b)/8)):
    #         bs.append(chr(int("".join([ str(x) for x in b[i*8:(i+1)*8] ]),2)))
    # return "".join(bs)
    c = int(b, base =2)
    string = c.to_bytes((c.bit_length() + 7) // 8, 'big').decode()
    return string
def strToBin(m):
	return "".join(format(ord(c), 'b').zfill(8) for c in m)

def binary_to_number(input):
    result = int(input, base =2)
    return result


def number_to_binary(input):
    return "{0:b}".format(input)

def binary_to_numberArray(input):
    array = [input[i:i+7] for i in range(0, len(input), 7)]
    result = [int(x, base =2)  for x in array]

    return result

def string_to_binary(input):
    result = "".join(["{0:b}".format(ord(x))  for x in input])
    return result

def binary_to_string(input):
    array = [input[i:i+7] for i in range(0, len(input), 7)]
    result = "".join([chr(int(x, base =2))  for x in array])
    return result

def numberArray_to_binary(input):
    result = "".join(["{0:b}".format(x)  for x in input])
    return result

def binary_to_stringNumber(input):
    result = int(input, base =2)
    result = str(result)
    return result

def stringNumber_to_binary(input):
    return "{0:b}".format(int(input))


def keyGeneration_ntru(securityLevel):
    param = ntruStandart.NTRUParams(securityLevel,'speed')
    private_key = ntruStandart.NTRUKey(param)
    public_key = private_key.publicKey()
    return private_key, public_key

def keyGeneration_ecc(securityLevel):
    if securityLevel == 112:
        keySize = 224
    elif securityLevel == 128:
        keySize = 256
    elif securityLevel == 192:
        keySize = 384
    elif securityLevel == 256:
        keySize = 521
    public_key, private_key = ecdsa.keypair(keySize)
    return private_key, public_key

def keyGeneration_elgamal(securityLevel): 
    if securityLevel == 112:
        keySize = 224
    elif securityLevel ==128:
        keySize = 256
    elif securityLevel == 192:
        keySize = 384
    elif securityLevel == 256:
        keySize = 512
    key = elgamal.generate_keys(keySize,32)
    return key["privateKey"], key["publicKey"]

def keyGeneration_rsa(securityLevel): 
    if securityLevel == 112:
        keySize = 2048
    elif securityLevel ==128:
        keySize = 3072
    elif securityLevel == 192:
        keySize = 7680
    elif securityLevel == 256:
        keySize = 15360
    (bob_pub, bob_priv) = rsa.newkeys(keySize)
    return bob_priv, bob_pub

def get_key_ntru(securityLevel) :
    private_key = keyLib.ntrukey(securityLevel)
    public_key = private_key.publicKey()
    return private_key, public_key

def get_key_elgamal(securityLevel) :
    if securityLevel == 112:
        get_key = 0
    elif securityLevel ==128:
        get_key = 1
    elif securityLevel == 192:
        get_key = 2
    elif securityLevel == 256:
        get_key = 3
    private_key = elgamal.PrivateKey(keyLib.p_elgamal[get_key], keyLib.g_elgamal[get_key], keyLib.x_elgamal[get_key], keyLib.iNumBits_elgamal[get_key])
    public_key = elgamal.PublicKey(keyLib.p_elgamal[get_key], keyLib.g_elgamal[get_key], keyLib.h_elgamal[get_key], keyLib.iNumBits_elgamal[get_key])
    return private_key, public_key

def get_key_rsa(securityLevel) :
    if securityLevel == 112:
        get_key = 0
    elif securityLevel ==128:
        get_key = 1
    elif securityLevel == 192:
        get_key = 2
    elif securityLevel == 256:
        get_key = 3
    private_key = rsa.PrivateKey(keyLib.n_rsa[get_key], keyLib.e_rsa, keyLib.d_rsa[get_key], keyLib.p_rsa[get_key], keyLib.q_rsa[get_key])
    public_key = rsa.PublicKey(keyLib.n_rsa[get_key], keyLib.e_rsa)
    return private_key, public_key

def encryption_ntru(public_key, plaintext):
    ciphertext = ntruStandart.NTRUEncrypt(public_key[0], public_key[1], plaintext)
    return ciphertext

def decryption_ntru(private_key, ciphertext, q):
    plaintext = ntruStandart.NTRUDecrypt(private_key, ciphertext, q)
    return plaintext

# def encryption_ntru_binary(public_key, plaintext_bin):
#     plaintext_bin_array = list(map(int,list(plaintext_bin)))
#     print(plaintext_bin_array)
#     ciphertext = ntruStandart.NTRUEncryptBinary(public_key[0], public_key[1], plaintext_bin_array)
#     return ciphertext

# def decryption_ntru_binary(private_key, ciphertext, q):
#     plaintext_bin = ntruStandart.NTRUDecryptBinary(private_key, ciphertext, q)
#     plaintext_bin = ''.join(str(x) for x in (plaintext_bin))
    return plaintext_bin
def encryption_ntru_binary(public_key, plaintext_bin):
    # plaintext_bin_array = list(map(int,list(plaintext_bin)))
    ciphertext = ntruStandart.NTRUEncryptBinary(public_key[0], public_key[1], plaintext_bin)
    return ciphertext

def decryption_ntru_binary(private_key, ciphertext, q):
    plaintext_bin = ntruStandart.NTRUDecryptBinary(private_key, ciphertext, q)
    # plaintext_bin = ''.join(str(x) for x in (plaintext_bin))
    return plaintext_bin
def encryption_ecc(public_key, plaintext):
    ciphertext = eccrypt.encrypt(plaintext, public_key)
    # print(ciphertext[0])
    return ciphertext

def decryption_ecc(private_key, ciphertext):
    plaintext = eccrypt.decrypt(ciphertext[0], ciphertext[1], private_key)
    return plaintext

def encryption_ecc_binary(public_key, plaintext_bin):
    input = binary_to_string(plaintext_bin)
    ciphertext = eccrypt.encrypt(input, public_key)
    return ciphertext

def decryption_ecc_binary(private_key, ciphertext):
    plaintext = eccrypt.decrypt(ciphertext[0], ciphertext[1], private_key)
    plaintext_bin = string_to_binary(plaintext)
    return plaintext_bin

def encryption_elgamal(public_key, plaintext):
    ciphertext = elgamal.encrypt(public_key, plaintext)
    return ciphertext

def decryption_elgamal(private_key, ciphertext):
    plaintext = elgamal.decrypt(private_key, ciphertext)
    return plaintext

def encryption_elgamal_binary(public_key, plaintext_bin):
    plaintext = binary_to_string(plaintext_bin)
    ciphertext = elgamal.encrypt(public_key, plaintext)
    return ciphertext

def decryption_elgamal_binary(private_key, ciphertext):
    plaintext = elgamal.decrypt(private_key, ciphertext)
    plaintext_bin = string_to_binary(plaintext)
    return plaintext_bin

def encryption_rsa(public_key, plaintext):
    plaintext = plaintext.encode('utf8')
    ciphertext = rsa.encrypt(plaintext, public_key)
    return ciphertext

def decryption_rsa(private_key, ciphertext):
    plaintext = rsa.decrypt(ciphertext, private_key)
    plaintext = plaintext.decode('utf8')
    return plaintext

def encryption_rsa_binary(public_key, plaintext_bin):
    plaintext = binary_to_string(plaintext_bin)
    plaintext = plaintext.encode('utf8')
    ciphertext = rsa.encrypt(plaintext, public_key)
    return ciphertext

def decryption_rsa_binary(private_key, ciphertext):
    plaintext = rsa.decrypt(ciphertext, private_key)
    plaintext = plaintext.decode('utf8')
    plaintext_bin = string_to_binary(plaintext)
    return plaintext_bin
