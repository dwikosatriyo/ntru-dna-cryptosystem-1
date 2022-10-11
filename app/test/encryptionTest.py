from pickle import FALSE
import sys, os, binascii, time, math

from sympy import false, public
# sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntruEnc','ntru')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntruEnc')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntru1Enc')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntru3Enc')))
# sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntruEnc','PyNTRU')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','elgamalEnc')))
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','eccEnc')))
# sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ecc3Enc')))
sys.path.append(os.path.abspath(os.path.join('app','process','steganography','subtitutionDNA')))
sys.path.append(os.path.abspath(os.path.join('app','process')))
sys.path.append(os.path.abspath(os.path.join('app','cryptography')))
import rsa, elgamal, eccrypt, ecdsa, subtitutionDNA, ntruStandart, ntruRun, encryption, keyLib
from ntru1 import ntrucipher, mathutils

from rsa import transform
import ntru,fracModulo,poly, random
from fractions import Fraction as frac
from operator import add
from operator import neg



# bit_length = [10,100,1000,10000,10000,100000]
def binToStr(b):
        bs = []
        for i in range(int(len(b)/8)):
                bs.append(chr(int("".join([ str(x) for x in b[i*8:(i+1)*8] ]),2)))
        return "".join(bs)
def strToBin(m):
	return "".join(format(ord(c), 'b').zfill(8) for c in m)
def binToDNA(b):
        dna_array = []
        for i, j in zip(b[::2], b[1::2]):
        # for i in [binary[i:i+2] for i in range(0, len(binary), 2)] <= sama
                if i+j == '00':
                        # seq=seq+'A'
                        dna_array.append(-1)
                elif i+j == '01':
                        # seq=seq+'C'
                        dna_array.append(0) 
                elif i+j == '10':
                        # seq=seq+'G'
                        dna_array.append(1) 
                elif i+j == '11':
                        # seq=seq+'U'
                        dna_array.append(2)
        # seq = "".join(dna_array)
        return dna_array
# print(binToStr(input))
security_level = 256



input = "a"*1000
input_bin = "1"*70

# print(input)
# private_key_ntru, public_key_ntru = encryption.keyGeneration_ntru(security_level)
# start_time = time.time_ns()


# print(private_key_ntru.ring.N)
# print(private_key_ntru.ring.d_f)
# print(private_key_ntru.ring.q)
# print(private_key_ntru.ring.p)

# print(private_key_ntru.f)
# print(private_key_ntru.finvp)
# print(private_key_ntru.h)


# key = keyLib.ntrukey(security_level)
# private_key_ntru = key
# public_key_ntru = key.publicKey()

# start_time = time.time_ns()
# ciphertext = encryption.encryption_ntru(public_key_ntru, input)
# print()
# print("Total = ",end="")
# print((time.time_ns() - start_time)/ (10 ** 9))
# plain = encryption.decryption_ntru(private_key_ntru, *ciphertext)

# print(ciphertext)
# print(plain)
# input_dna = "-2"*35
# start_time = time.time_ns()
# input_dna = [1]*7000

# ciphertext = encryption.encryption_ntru_binary(public_key_ntru, input_dna)
# print()
# print("Total = ",end="")
# print((time.time_ns() - start_time)/ (10 ** 9))
# plain = encryption.decryption_ntru_binary(private_key_ntru, *ciphertext)
# print(input_dna)
# print(plain)
# print(plain==input_dna)


# decrypted = encryption.decryption_ntru(private_key_ntru, *ciphertext)

# print(decrypted)

# print(key.f)


# print()
# print("Total = ",end="")
# print((time.time_ns() - start_time)/ (10 ** 9))
# public_key = private_key.publicKey()

# a = encryption.binary_to_string(input_bin)
# print(a)
# b = encryption.string_to_binary(a)
# print(b)
# print(input_bin)

## Key
###################################################################################
private_key_ntru, public_key_ntru = encryption.get_key_ntru(security_level)
private_key_ecc, public_key_ecc = encryption.keyGeneration_ecc(security_level)
private_key_elgamal, public_key_elgamal = encryption.get_key_elgamal(security_level)
private_key_rsa, public_key_rsa = encryption.get_key_rsa(security_level)
###################################################################################

## NTRU
###################################################################################
print("NTRU")
start_time = time.time_ns()
ciphertext = encryption.encryption_ntru(public_key_ntru, input)
decrypted = encryption.decryption_ntru(private_key_ntru, *ciphertext)
print((time.time_ns() - start_time)/ (10 ** 9))
print(decrypted==input)
# print()
# start_time = time.time_ns()
# ciphertext = encryption.encryption_ntru_binary(public_key_ntru, input_bin)
# decrypted = encryption.decryption_ntru_binary(private_key_ntru, *ciphertext)
# print((time.time_ns() - start_time)/ (10 ** 9))
# print(decrypted==input_bin)
###################################################################################

## ECC
###################################################################################
print("ECC")
start_time = time.time_ns()
ciphertext = encryption.encryption_ecc(public_key_ecc, input)
decrypted = encryption.decryption_ecc(private_key_ecc, ciphertext)
print((time.time_ns() - start_time)/ (10 ** 9))
print(decrypted==input)
# print()
# start_time = time.time_ns()
# ciphertext = encryption.encryption_ecc_binary(public_key_ecc, input_bin)
# decrypted = encryption.decryption_ecc_binary(private_key_ecc, ciphertext)
# print((time.time_ns() - start_time)/ (10 ** 9))
# print(decrypted==input_bin)
###################################################################################

## El Gamal
###################################################################################
print("El Gamal")
start_time = time.time_ns()
ciphertext = encryption.encryption_elgamal(public_key_elgamal,input)
decrypted = encryption.decryption_elgamal(private_key_elgamal,ciphertext)
print((time.time_ns() - start_time)/ (10 ** 9))
print(decrypted==input)
# print()
# start_time = time.time_ns()
# ciphertext = encryption.encryption_elgamal_binary(public_key_elgamal,input_bin)
# decrypted = encryption.decryption_elgamal_binary(private_key_elgamal,ciphertext)
# print((time.time_ns() - start_time)/ (10 ** 9))
# print(decrypted==input_bin)
###################################################################################

## RSA
###################################################################################
print("RSA")
start_time = time.time_ns()
ciphertext = encryption.encryption_rsa(public_key_rsa ,input)
decrypted = encryption.decryption_rsa(private_key_rsa,ciphertext)
print((time.time_ns() - start_time)/ (10 ** 9))
print(decrypted==input)
# print()
# start_time = time.time_ns()
# ciphertext = encryption.encryption_rsa_binary(public_key_rsa ,input_bin)
# decrypted = encryption.decryption_rsa_binary(private_key_rsa,ciphertext)
# print((time.time_ns() - start_time)/ (10 ** 9))
# print(decrypted==input_bin)
###################################################################################



# a = (strToBin("input"))
# print(binToStr(a))
# privat, publik = encryption.get_key_rsa(112)
# encryption.encryption_rsa(publik, "pesan")

# print("pesan".encode('utf8'))
# encryption.encryption_rsa_binary(publik, input)
# print(test_analysis.analysisEnc(256))

# start_time = time.time_ns()
# print(encryption.keyGeneration_ntru(112))
# print(encryption.keyGeneration_ntru(128))
# print(encryption.keyGeneration_ntru(192))
# print(encryption.keyGeneration_ntru(256))
# print((time.time_ns() - start_time)/ (10 ** 9))
# start_time = time.time_ns()
# m = list(map(int,list(ntruStandart.strToBin(""))))
# print((time.time_ns() - start_time))
# print(m)

# private_key, public_key = encryption.keyGeneration_ecdsa(112)
# # print(public_key)
# cipher = eccrypt.encrypt(binToStr(input), public_key)

# print(cipher)

# decrypt = eccrypt.decrypt(cipher[0], cipher[1], private_key)
# # decrypt = encryption.decryption_ntru(key, encrypt[0], encrypt[1])

# print(decrypt)

# result = strToBin(decrypt)

# print(result)
















# msg = 'hello Bob!'
# keySize = 256

# msg = "p"

# a = "18028077577853770265650308534081671136211462373532133696917255124793 11645027812982171661320929009306447247432731252116556182334927225423"
# plaintext = a.encode()
# # print([bin(x)[2:].zfill(7) for x in plaintext])
# bin_plaintext = "".join([bin(x)[2:].zfill(7) for x in plaintext])

# # print(bin_plaintext)

# message_binary = [bin_plaintext[i:i+7] for i in range(0, len(bin_plaintext), 7)]
# # print(message_binary)
# message = [subtitutionDNA.binstring_to_string(x) for x in message_binary]
# # print(message)
# message = ''.join(message)
# print(message)

# a = b'|\x02\x0f"\xe0\xed\x0c\xf5m\x16\xd4\xf4\xdaK*9\xe6\x92\xd8\x9c#(\xde\x81\x93\xb3,Q{\xa8Oxc\xee\xbe\xdbL9\xe2g\xf8\x81H\x03=\x82u\x8d\xb9I\x13\x99i\xde\xaaxs\x99%\xea,\x9f\xc0\xf8\x88\xca\xd9G\xee\xc6\xe9\x93\xb7\x8c\x81\xce\xdb\xd8]|@3 \xabj\xd3\xc1\xe6J\xda\xc8\xec_a\x80\x07\xd4\xecp\x89\x00J\x9eu\xa9N\x00\xe2k\xa9\x1c"\xe5\x04\xe3\xd1\x1eh\xafV\xd7\x852\r\xfep{\x003\x97\xa1\x99\x19\xc2\xcd\xceu\xed\xac\xd4\x04\x01\xb7\xads\xa0][\xd4\x02\xa2\xed\xb6\x9ev>\xe8\xde\xd1\xa6\xa0{\xdb\xda.\xf1\x91\xd3\x02\x8a<\x05\xa4\x8eK\x08\xdc\xbdj\xda\x04+N\x1d\xce\x83\xd0\xef\xe2v\xdcT\xbey\xf2E0_\x89A\x158(\xd4\xc0\xf56!\xd1\\]MB\xeb\xc40i\xd0M\x10s\xde\xb4\\\xd2\x81S\x0b\x8d\xc1BZ\xef"\xba\xec\xf7\x9eH\x834\xf6iB\x19\xcbo\x11\xe6[2\x00\xeb\xd67\xec'
# print(a)

# b = transform.bytes2int(a)
# print(b)
# c = bin(b)[2:]

# d = int(c, base =2)
# print(d)
# string = transform.int2bytes(d)
# print(string)

# print(transform.int2bytes(b))
# print(bytes(a,'UTF-8'))

# b = str(a)[2:-1]
# c = bytes(b, encoding="raw_unicode_escape")
# print(c)

# param = ntruStandart.NTRUParams(112,'speed')
# key = ntruStandart.NTRUKey(param)
# m = list(map(int,list(ntruStandart.strToBin(msg))))
# print(m)
# if len(m) > key.ring.N:
#         msplit = [ m for m in ntruStandart.chunk(key.ring.N, m) ]
#         n = len(msplit[-1])
#         m = [ntruStandart.ConvPoly(m, key.ring.N) for m in msplit]
# else:
#         n = len(m)
#         m = [ntruStandart.ConvPoly(m, key.ring.N)]
        
# menc = [ntruStandart.NTRUBlockEncrypt(key.ring, key.h, m) for m in m]
# print(menc)
# print(menc[0].coef)
# if len(menc)==1:
#         m = ntruStandart.NTRUBlockDecrypt(key, menc[0])
        
#         m = ntruStandart.binToStr(m.coef[:n])
# print(m)
# number = [1112,1114,5342,3212]

# result = "".join([bin(x)[2:].zfill(14) for x in number])
# # binary = bin(10000)[2:].zfill(14)
# print(result)

# number = [result[i:i+14] for i in range(0, len(result), 14)]

# print (number)
# plain = [int(i, base =2) for i in number]
# print (plain)
# c = int(result, base =2)

# print(number)
# for i, j in zip(result[::2], result[1::2]):
#         print (i)
# print(binary)
# c = int(binary, base =2)
# print(c)

# msg_bin = "".join(format(ord(c), 'b').zfill(8) for c in msg)
# print(msg_bin)
# print(list(map(int,list(msg_bin))))

# print (random.getrandbits(10))

# print("{0:b}".format(random.getrandbits(10)).zfill(8))



# start_time = time.time_ns()
# param = ntruStandart.NTRUParams(keySize,'speed')
# key = ntruStandart.NTRUKey(param)
# # print((time.time_ns() - start_time)/ (10 ** 9))

# print(key)


# # start_time = time.time_ns()
# enc = ntruStandart.NTRUEncrypt(key.ring, key.h, msg)
# # print((time.time_ns() - start_time)/ (10 ** 9))

# # start_time = time.time_ns()
# m = ntruStandart.NTRUDecrypt(key, *enc)
# print((time.time_ns() - start_time)/ (10 ** 9))




# keySize = 112
# start_time = time.time()
# param = ntruStandart.NTRUParams(keySize,'hoffstein')
# key = ntruStandart.NTRUKey(param)
# # print(key.publicKey()[1])
# key_generation = time.time() - start_time
# print("key generation = ",end = "")
# print(key_generation)
# start_time = time.time()
# enc = ntruStandart.NTRUEncrypt(key.ring, key.h, plaintext)
# encryption = time.time() - start_time
# print("encryption = ",end = "")
# print(encryption)
# start_time = time.time()
# m = ntruStandart.NTRUDecrypt(key, *enc)
# decryption = time.time() - start_time
# print("decryption = ",end = "")
# print(decryption)


# start_time = time.time()
# key = elgamal.generate_keys(512,32)

# key_generation = time.time() - start_time
# print("key generation = ",end = "")
# print(key_generation)
# start_time = time.time()

# # print(time.time() - start_time)
# #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
# # start_time = time.time()

# cipher = elgamal.encrypt(key["publicKey"], msg)
# encryption = time.time() - start_time
# print("encryption = ",end = "")
# print(encryption)
# # print(time.time() - start_time)

# start_time = time.time()
# plaintext = elgamal.decrypt(key["privateKey"], cipher)
# decryption = time.time() - start_time
# print("decryption = ",end = "")
# print(decryption)


# print("ntru1enc")
# N = 743
# q = 2048
# p = 3

# ntru = ntrucipher.NtruCipher(N,p,q)
# ntru.generate_random_keys()
# # random_poly = mathutils.random_poly(ntru.N, int(math.sqrt(ntru.q)))
# message = ntru.encryptMessage(msg)
# print(message)
# # print(ntru.h_poly)



# print("ecies")
# start_time = time.time()
# key = eccCrypt.generate_keypair("secp521r1/nistp521")
# print(key)
# pw = key[0]
# pk = str(eccCrypt.passphrase_to_pubkey(pw))
# ecc_ciphertext = eccCrypt.encrypt(msg.encode('ascii'), pk)
# ecc_encrypted = eccCrypt.decrypt(ecc_ciphertext, pw)
# # print(ecc_encrypted)
# print(time.time() - start_time)


# print("ecdsa")
# start_time = time.time()
# key = ecdsa.keypair(521)
# # times.append(time.time() - start_time)
# #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
# print(key)
# # start_time = time.time()
# cipher = eccrypt.encrypt(msg, key[0])

# # times.append(time.time() - start_time)
# # print(cipher[1])
# # start_time = time.time()
# plaintext = eccrypt.decrypt(cipher[0], cipher[1], key[1])
# print(time.time() - start_time)


# print("rsa")
# start_time = time.time()
# (bob_pub, bob_priv) = rsa.newkeys(2048)
# # n = 20553656739605268126644932250724207751039639247014579568208581429880675400343300150300450736591413449055678122677018042470346063096723647430785944574159719574993438191464992744127369877454482885962504306761290599068164813483562789415186639548707485790929227091500665572995342039716100752273246629630851832514087840865801845973240234776451733222592935368631367829642847723449774653586566946861777708916118588345713165526592572907288577172478983124983704262010180013847869124387190079691379162685880483913373467759448008543778638838420749927409625270817026973822728680398600945055804428524500381461065890516055401035477
# # e = 65537
# # d = 15291441404239950918091362233254664106156686000365242085947083530801256865128684998220079909283673908617372688793903378469706171238690382553828540908904582251820041493193922764517178090009089164193658314983398798073845003216985130327992892123775570932360761928794260524712862767176978508006652399982969879933347971420190636195390252428814315353864040683017347475049882026169756622059265724921832648049447171056278992300880676959611859711336315515922520359749255062494685098258553431015474268698279939246806905149382281378422289873128501027173810302229662148707889818531041459720182758379578968417833897902288130217993
# # p = 2194118500700944020059660814014780787265672251631881705583553399945645559839197235509478961998361661453775119260670214265200631243047227593244554944380130470270419132374140041676096228746400897661392271704176391545297559078497887277796439274520233638098946094302792645058707209417668957726100652939774312590047980123603484865367
# # q = 9367614708612636288523150791060850706392225725124032785586272852070306641038036299730789371473133043194470361700556785994014100945631648805060206757512259095060578424192045556927294242805271709034383586722974720380657318004341219123163046987559327547070824357799885409850918989558910097331

# # bob_pub = rsa.PublicKey(n,e)
# # bob_priv = rsa.PrivateKey(n,e,d,p,q)

# print(bob_pub)
# print(bob_priv)

# # print(len(str(bob_pub.__getstate__()[0])))
# message = msg.encode('utf8')
# crypto = rsa.encrypt(message, bob_pub)

# message = rsa.decrypt(crypto, bob_priv)
# # print(message.decode('utf8'))
# print(time.time() - start_time)


# start_time = time.time()
# key = elgamal.generate_keys(224,32)

# print("private key")
# print("p = ",end="")
# print(key["privateKey"].p)
# print("g = ",end="")
# print(key["privateKey"].g)
# print("x = ",end="")
# print(key["privateKey"].x)
# print("iNumBits = ",end="")
# print(key["privateKey"].iNumBits)
# print("public key")
# print("p = ",end="")
# print(key["publicKey"].p)
# print("g = ",end="")
# print(key["publicKey"].g)
# print("h = ",end="")
# print(key["publicKey"].h)
# print("iNumBits = ",end="")
# print(key["publicKey"].iNumBits)
# # print(time.time() - start_time)
# #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
# # start_time = time.time()

# cipher = elgamal.encrypt(key["publicKey"], msg)

# # print(time.time() - start_time)

# # start_time = time.time()
# plaintext = elgamal.decrypt(key["privateKey"], cipher)
# print(time.time() - start_time)








# start_time = time.time()
# key = ecdsa.keypair(521)
# print(len(str(key[0][1][0])))
# #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
# cipher = eccrypt.encrypt("hello Bob!", key[0])
# print(cipher)

# plaintext = eccrypt.decrypt(cipher[0], cipher[1], key[1])
# print(plaintext)

# print(time.time() - start_time)


# start_time = time.time()
# key = elgamal.generate_keys(512,32)

# # print(time.time() - start_time)
# #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
# # start_time = time.time()

# cipher = elgamal.encrypt(key["publicKey"], "hello Bob!")

# # print(time.time() - start_time)

# # start_time = time.time()
# plaintext = elgamal.decrypt(key["privateKey"], cipher)
# print(time.time() - start_time)












# from parameters import Standard
# from poly import Polynomial
# from ntru_poly_ops import invert_in_p, invert_in_2tor
# from poly import Polynomial as poly
# import Crypto.Random.random as CR

# from ntrucipher import NtruCipher
# from mathutils import random_poly
# import math
# from sympy.abc import x
# from sympy import ZZ, Poly
# import numpy as np
# import logging
# from sympy import GF, invert

# import unittest

# class TestSimpleEncrypt(unittest.TestCase):

#     def test_full_run(self):
#         x = Standard()
#         f = [-1,1,1,0,-1,0,1,0,0,1,-1]
#         g = [-1,0,1,1,0,1,0,0,-1,0,-1]
#         # f = [-1,1,0,0,1,0,-1,0,1,1,-1]
#         # g = [-1,0,-1,0,0,1,0,1,1,0,-1]
#         # f = x.gen_fPoly()
#         # g = x.gen_gPoly()
#         print(f)
#         print(g)
#         f = poly(f, x._N)
#         g = poly(g, x._N)
#         # print(f)
#         # print(g)
#         fp = invert_in_p(f, x.get_N())
#         fq = invert_in_2tor(f, x.get_N(), 5)
#         print(fp)
#         print(fq)

        # h = fq*g

        # m = Polynomial([-1,0,1,1,1,-1,0,0,0,0,-1,1,1,0,1,1,0,-1,1], x.get_N())

        # r = x.gen_rPoly()
        # e = (r.scale(x.get_p())*h + m) % x.get_q()

        # a = (f*e) % x.get_q()
        # b = (fp*a) % x.get_p()
        
        # self.assertEqual(b,m)

# unittest.main()















# N = 11
# p = 3
# q = 32
# ntru = NtruCipher(N, p, q)
# # ntru.generate_random_keys()

# f = [-1,1,1,0,-1,0,1,0,0,1,-1]
# g = [-1,0,1,1,0,1,0,0,-1,0,-1]
# # f = [-1,1,0,0,1,0,-1,0,1,1,-1]
# # g = [-1,0,-1,0,0,1,0,1,1,0,-1]
# f = Poly(f[::-1], x).set_domain(ZZ)
# g = Poly(g[::-1], x).set_domain(ZZ)

# # print(f)
# # print(g)

# ntru.generate_public_key(f,g)
# print(ntru.f_p_poly.all_coeffs()[::-1])
# # # print(ntru.f_q_poly.all_coeffs()[::-1])
# # print(ntru.f_p_poly)
# # print(ntru.f_q_poly)
# # plaintext = "P"
# # plaintext = plaintext.encode('ascii')
# # # print(plaintext)
# # ciphertext = ""
# # secrettext = ""
# # # print(len(plaintext))
# # if ntru.N < len(plaintext):
# #     ciphertext = ntru.encrypt(Poly(plaintext[::-1], x).set_domain(ZZ),
# #                                random_poly(ntru.N, int(math.sqrt(ntru.q)))).all_coeffs()[::-1]
# # else :
# #     # print("error")
# # # k = int(math.log2(ntru.q))
# # # ciphertext = [[0 if c == '0' else 1 for c in np.binary_repr(n, width=k)] for n in ciphertext]
# # # ciphertext = np.array(ciphertext).flatten()
# # # print(ciphertext)
# # if ntru.N < len(ciphertext):
#     secrettext = ntru.decrypt(Poly(ciphertext[::-1], x).set_domain(ZZ)).all_coeffs()[::-1]
# else :
#     # print("error")
# # print(secrettext)
# plaintext = "pesan"
# reference = "ACGACGACGACGGGACGACGACGACGACGGGACGACGACGACGACGGGACGACGACGACGACGGGACG"

# steganograph = subtitutionDNA.subtitution_embed(plaintext, reference)
# plaintext = subtitutionDNA.subtitution_extract(steganograph, reference)

# print (plaintext)



















# f = "1 2 3 4"

# f = f.split()
# f = list(map(int, f))
# print(f)








# key = elgamal.generate_keys(10,2771)
# #returns a dictionary {'privateKey': privateKeyObject, 'publicKey': publicKeyObject}
# cipher = elgamal.encrypt(key["publicKey"], "This is the message I want to encrypt")

# plaintext = elgamal.decrypt(key["privateKey"], cipher)

# print(cipher)
# print(plaintext)






















































# f=[-1,1,1,0,-1,0,1,0,0,1,-1]
# g=[-1,0,1,1,0,1,0,0,-1,0,-1]
# d=2
# encNtru = ntru.Ntru(11,3,32)

# encNtru.genPublicKey(f,g,d)
# publicKey = encNtru.getPublicKey()
# Alice=ntru.Ntru(11,3,32)
# Alice.setPublicKey(publicKey)
# plaintext = "plaintex"
# plaintext = [ord(character) for character in plaintext]
# plaintext = [str(int(bin(character)[2:])) for character in plaintext]
# plaintext = "".join(plaintext)
# plaintext = [int(char) for char in plaintext]
# print(plaintext)
# ranPol=[-1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1]
# encrypt_msg=Alice.encrypt(plaintext,[-1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1,-1,1,1])
# print(encrypt_msg)

# print (encNtru.decrypt(encrypt_msg))




# f=[-1,1,1,0,-1,0,1,0,0,1,-1]
# # f=[-1,0,1,1]
# q=32
# N=len(f)

# D=[0]*(N+1)
# D[0]=-1
# D[N]=1
# print ("D: ",D)

# [gcd_f,s_f,t_f]=poly.extEuclidPoly(f,D)



# s_f=poly.modPoly(s_f,q)
# print ("f=",f)
# print ("\ns_f=",s_f)


# f_p=poly.multPoly(f,s_f)

# print ("f x s_f=",f_p)
# h=poly.reModulo(f_p,D,q)

# print ("Res: ",h)


# N=50
# p=7
# q=89

# f=[-1,1,1,0,-1,0,1,0,0,1,-1]
# g=[-1,0,1,1,0,1,0,0,-1,0,-1]


# print("==== Bob generates public key =====")
# print("Values used:")
# print(" N=",N)
# print(" p=",p)
# print(" q=",q)
# print("========")
# print("\nBob picks two polynomials (g and f):")

# f=[1,1,-1,0,-1,1]
# g=[-1,0,1,1,0,0,-1]
# #f=[-1,0,1,1,-1,0,-1]
# #g=[0,-1,-1,0,1,0,1]

# d=2

# print("f(x)= ",f)
# print("g(x)= ",g)



# D=[0]*(N+1)
# D[0]=-1
# D[N]=1


# print("\n====Now we determine F_p and F_q ===")
# [gcd_f,s_f,t_f]=poly.extEuclidPoly(f,D)

# f_p=poly.modPoly(s_f,p)
# f_q=poly.modPoly(s_f,q)
# print("F_p:",f_p)
# print("F_q:",f_q)

# x=poly.multPoly(f_q,g)
# h=poly.reModulo(x,D,q)

# print("\n====And finally h====")
# print("f_q x g: ",x)
# print("H (Bob's Public Key): ",h)

# print("\n====Let's encrypt====")
# msg=[1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,1,0,0,0,0,0,0,0,0]
# print(len(msg))
# # for i in range(len(msg)-1,0,-1):
# #         if msg[i] == 0:
# #                 msg[i] = -1
# #         else :
# #                 break
# if msg[len(msg)-1] == 0:
#     msg[len(msg)-1] = 2
# randPol=[-1,-1,1,1]

# print("Alice's Message:\t",msg)
# print("Random:\t\t\t",randPol)
# e_tilda=poly.addPoly(poly.multPoly(poly.multPoly([p],randPol),h),msg)
# e=poly.reModulo(e_tilda,D,q)

# print("Encrypted message:\t",e)

# print("\n====Let's decrypt====")

# tmp=poly.reModulo(poly.multPoly(f,e),D,q)
# centered=poly.cenPoly(tmp,q)
# m1=poly.multPoly(f_p,centered)
# tmp=poly.reModulo(m1,D,p)

# print("Decrypted message:\t",poly.trim(tmp))