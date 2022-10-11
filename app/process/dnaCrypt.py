from asyncio.windows_events import NULL
import sys, os
import time
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography')))
sys.path.append(os.path.abspath(os.path.join('app','process','steganography')))
import test, subtitutionDNA, rsa
from itertools import chain
from ntru3Enc import ntruStandart
from eccEnc import ecdsa, eccrypt
from elgamalEnc import elgamal


def ntru_arraytobinary_converter(input):
    result = "".join([bin(x)[2:].zfill(14) for x in input])
    
    return result

def ntru_binarytoarray_converter(input):
    number = [input[i:i+14] for i in range(0, len(input), 14)]
    result = [int(i, base =2) for i in number]
    
    return result

def dnaCryptTime(securityLevel , dna_cover, plaintext):
    
    media_dna = ''
    file1 = NULL
    securityLevel = int(securityLevel)
    dna_filePath = os.path.abspath(os.path.join('files','dna','dnaMedia'))
    if (dna_cover == "1"):
        file1 = open(os.path.join(dna_filePath,'X98392.txt'),"r")
    elif (dna_cover == "2"):
        file1 = open(os.path.join(dna_filePath,'MN988668.txt'),"r")
    elif (dna_cover == "3"):
        file1 = open(os.path.join(dna_filePath,'AC073210.8.fasta'),"r")
    elif (dna_cover == "4"):
        file1 = open(os.path.join(dna_filePath,'NC_045512.2.fasta'),"r")

    media_dna = file1.read().replace(' ','').replace('\n','')

    all_times = []
    times = []
    keySize = securityLevel
    start_time = time.time_ns()
    param = ntruStandart.NTRUParams(keySize,'speed')
    key = ntruStandart.NTRUKey(param)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # print(plaintext)

    start_time = time.time_ns()
    enc = ntruStandart.NTRUEncrypt(key.ring, key.h, plaintext)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    # m = ntruStandart.binToStr(m)
    # print(enc[0][0].coef)
    m = ntru_arraytobinary_converter(enc[0][0].coef)
    # print(m)
    start_time = time.time_ns()
    embed = subtitutionDNA.subtitution_embed_binary(m,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    extract = subtitutionDNA.subtitution_extract_binary(embed,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # print(extract)
    m = ntru_binarytoarray_converter(extract)
    # print(m)
    msplit = [ m for m in ntruStandart.chunk(key.ring.N, m) ]
    n = len(msplit[-1])
    m = [ntruStandart.ConvPoly(m, key.ring.N) for m in msplit]
    # print(m)
    start_time = time.time_ns()
    m = ntruStandart.NTRUDecrypt(key, m, enc[1])
    print(m)
    print()
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)
    
    all_times.append(times)

    keySize = 0
    if securityLevel == 112:
        keySize = 224
    elif securityLevel == 128:
        keySize = 256
    elif securityLevel == 192:
        keySize = 384
    elif securityLevel == 256:
        keySize = 521

    times = []

    start_time = time.time_ns()
    key = ecdsa.keypair(keySize)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    cipher = eccrypt.encrypt(plaintext, key[0])
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # test = cipher[0].encode()
    # test = "".join([bin(x)[2:].zfill(9) for x in test])
    cipher_b = bin(int.from_bytes(cipher[0].encode(), 'big'))[2:]
    # print(cipher[0].encode())
    # print(bin(cipher[0].encode()))
    start_time = time.time_ns()
    embed = subtitutionDNA.subtitution_embed_binary(cipher_b,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    extract = subtitutionDNA.subtitution_extract_binary(embed,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    n = int(extract, 2)
    extract = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
    # print(extract)
    start_time = time.time_ns()
    plaintext = eccrypt.decrypt(extract, cipher[1], key[1])
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    print(plaintext)
    print()
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)
    all_times.append(times)

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
    key = elgamal.generate_keys(keySize,32)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    cipher = elgamal.encrypt(key["publicKey"], plaintext)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # print(cipher)
    start_time = time.time_ns()
    embed = subtitutionDNA.subtitution_embed(cipher,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    extract = subtitutionDNA.subtitution_extract(embed,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    # print(extract)
    start_time = time.time_ns()
    plaintext = elgamal.decrypt(key["privateKey"], extract)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    print(plaintext)
    print()
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)

    all_times.append(times)


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
    message = plaintext.encode('utf8')
    start_time = time.time_ns()
    crypto = rsa.encrypt(message, bob_pub)
    # print(crypto)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    crypto = rsa.transform.bytes2int(crypto)
    crypto = bin(crypto)[2:]
    # print(crypto)
    start_time = time.time_ns()
    embed = subtitutionDNA.subtitution_embed_binary(crypto,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))

    start_time = time.time_ns()
    extract = subtitutionDNA.subtitution_extract_binary(embed,media_dna)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    extract = int(extract, base =2)
    extract = rsa.transform.int2bytes(extract)
    # print(extract)
    start_time = time.time_ns()
    message = rsa.decrypt(extract, bob_priv)
    times.append((time.time_ns() - start_time)/ (10 ** 9))
    print(message)
    totaltimes = 0
    for i in times :
        totaltimes = totaltimes+i
    times.append(totaltimes)

    all_times.append(times)

    return all_times


