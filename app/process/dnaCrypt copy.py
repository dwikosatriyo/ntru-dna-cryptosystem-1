from asyncio.windows_events import NULL
import sys, os
import time
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography')))
sys.path.append(os.path.abspath(os.path.join('app','process','steganography')))
import test, subtitutionDNA, rsa

from ntru3Enc import ntruStandart
from eccEnc import ecdsa, eccrypt
from elgamalEnc import elgamal



def dnaCryptTime(securityLevel, encryption_method , dna_cover, plaintext):
    
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

    print(os.path.join(dna_filePath,'X98392.txt'))
    media_dna = file1.read().replace(' ','').replace('\n','')

    if encryption_method == "ntru":
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
        embed = subtitutionDNA.subtitution_embed(enc[0],media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        extract = subtitutionDNA.subtitution_extract(embed,media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        m = ntruStandart.NTRUDecrypt(key, extract, enc[1])
        times.append((time.time_ns() - start_time)/ (10 ** 9))
        totaltimes = 0
        for i in times :
            totaltimes = totaltimes+i
        times.append(totaltimes)
        
    elif encryption_method == "ecc":
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

        start_time = time.time_ns()
        embed = subtitutionDNA.subtitution_embed(cipher[0],media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        extract = subtitutionDNA.subtitution_extract(embed,media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        plaintext = eccrypt.decrypt(extract, cipher[1], key[1])
        times.append((time.time_ns() - start_time)/ (10 ** 9))
        
        totaltimes = 0
        for i in times :
            totaltimes = totaltimes+i
        times.append(totaltimes)
        return times
    elif encryption_method == "elGamal":
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

        start_time = time.time_ns()
        embed = subtitutionDNA.subtitution_embed(cipher,media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        extract = subtitutionDNA.subtitution_extract(embed,media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        plaintext = elgamal.decrypt(key["privateKey"], extract)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        totaltimes = 0
        for i in times :
            totaltimes = totaltimes+i
        times.append(totaltimes)

        return times
    elif encryption_method == "rsa":
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
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        embed = subtitutionDNA.subtitution_embed(crypto,media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        extract = subtitutionDNA.subtitution_extract(embed,media_dna)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        start_time = time.time_ns()
        message = rsa.decrypt(extract, bob_priv)
        times.append((time.time_ns() - start_time)/ (10 ** 9))

        totaltimes = 0
        for i in times :
            totaltimes = totaltimes+i
        times.append(totaltimes)

        return times


