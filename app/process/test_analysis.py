import sys, os
import time
# print(sys.path)
from app.process import encryption,dna


def analysisEnc (security_level):
    # algorithm = "ecc"
    # security_level = [112,128,192,256]
    # keySize_ntru = [112,128,192,256]
    # keySize_ecdsa = [224,256,384,521]
    plaintexts = []
    plaintexts.append("a"*10)
    plaintexts.append("a"*100)
    plaintexts.append("a"*1000)
    plaintexts.append("a"*10000)
    plaintexts.append("a"*100000)
    
    
    times_encrypt_ntru = []
    times_encrypt_ecc = []
    times_encrypt_elgamal = []
    times_encrypt_rsa = []
    times_decrypt_ntru = []
    times_decrypt_ecc = []
    times_decrypt_elgamal = []
    times_decrypt_rsa = []
    times_total_ntru = []
    times_total_ecc = []
    times_total_elgamal = []
    times_total_rsa = []
    private_key_ntru, public_key_ntru = encryption.get_key_ntru(security_level)
    private_key_ecc, public_key_ecc = encryption.keyGeneration_ecc(security_level)
    private_key_elgamal, public_key_elgamal = encryption.get_key_elgamal(security_level)
    private_key_rsa, public_key_rsa = encryption.get_key_rsa(security_level)
    for num, i in enumerate(plaintexts) : 
        print(len(i))
        times_encrypt_1 = []
        times_decrypt_1 = []
        times_encrypt_2 = []
        times_decrypt_2 = []
        times_encrypt_3 = []
        times_decrypt_3 = []
        times_encrypt_4 = []
        times_decrypt_4 = []
        for j in range(1) :
            print()
            print("ntru")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_ntru(public_key_ntru, i)
            times_encrypt_1.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_ntru(private_key_ntru, *ciphertext)
            times_decrypt_1.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            print("ecc")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_ecc(public_key_ecc, i)
            times_encrypt_2.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_ecc(private_key_ecc, ciphertext)
            times_decrypt_2.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            print("elgamal")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_elgamal(public_key_elgamal,i)
            times_encrypt_3.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_elgamal(private_key_elgamal,ciphertext)
            times_decrypt_3.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            if (num<2):
                print("rsa")
                start_time = time.time_ns()
                ciphertext = encryption.encryption_rsa(public_key_rsa ,i)
                times_encrypt_4.append((time.time_ns() - start_time)/ (10 ** 9))
                start_time = time.time_ns()
                decrypted = encryption.decryption_rsa(private_key_rsa,ciphertext)
                times_decrypt_4.append((time.time_ns() - start_time)/ (10 ** 9))
                print(i == decrypted)
            

        temp1 = sum(times_encrypt_1)/1
        temp2 = sum(times_decrypt_1)/1
        times_encrypt_ntru.append(temp1)
        times_decrypt_ntru.append(temp2)
        times_total_ntru.append(temp1+temp2)

        temp1 = sum(times_encrypt_2)/1
        temp2 = sum(times_decrypt_2)/1
        times_encrypt_ecc.append(temp1)
        times_decrypt_ecc.append(temp2)
        times_total_ecc.append(temp1+temp2)

        temp1 = sum(times_encrypt_3)/1
        temp2 = sum(times_decrypt_3)/1
        times_encrypt_elgamal.append(temp1)
        times_decrypt_elgamal.append(temp2)
        times_total_elgamal.append(temp1+temp2)
        if (num<2):
            temp1 = sum(times_encrypt_4)/1
            temp2 = sum(times_decrypt_4)/1
            times_encrypt_rsa.append(temp1)
            times_decrypt_rsa.append(temp2)
            times_total_rsa.append(temp1+temp2)
        # else : 
        #     temp1 = 0
        #     temp2 = 0
        

        times_encrypt_all = [times_encrypt_ntru,times_encrypt_ecc,times_encrypt_elgamal,times_encrypt_rsa]
        times_decrypt_all = [times_decrypt_ntru,times_decrypt_ecc,times_decrypt_elgamal,times_decrypt_rsa]
        times_total_all = [times_total_ntru,times_total_ecc,times_total_elgamal,times_total_rsa]
    


    return times_encrypt_all,times_decrypt_all,times_total_all

    
def analysisEncDna (security_level):
    # algorithm = "ecc"
    # security_level = [112,128,192,256]
    # keySize_ntru = [112,128,192,256]
    # keySize_ecdsa = [224,256,384,521]
    plaintexts = []
    plaintexts.append("a"*1)
    plaintexts.append("a"*10)
    plaintexts.append("a"*100)
    plaintexts.append("a"*1000)
    plaintexts.append("a"*10000)
    #plaintexts.append("a"*100000)
    plaintexts = [dna.string_to_DNA(x) for x in plaintexts]
    times_encrypt_ntru = []
    times_encrypt_ecc = []
    times_encrypt_elgamal = []
    times_encrypt_rsa = []
    times_decrypt_ntru = []
    times_decrypt_ecc = []
    times_decrypt_elgamal = []
    times_decrypt_rsa = []
    times_total_ntru = []
    times_total_ecc = []
    times_total_elgamal = []
    times_total_rsa = []
    private_key_ntru, public_key_ntru = encryption.get_key_ntru(security_level)
    private_key_ecc, public_key_ecc = encryption.keyGeneration_ecc(security_level)
    private_key_elgamal, public_key_elgamal = encryption.get_key_elgamal(security_level)
    private_key_rsa, public_key_rsa = encryption.get_key_rsa(security_level)
    for num, i in enumerate(plaintexts) : 
        print(len(i))
        times_encrypt_1 = []
        times_decrypt_1 = []
        times_encrypt_2 = []
        times_decrypt_2 = []
        times_encrypt_3 = []
        times_decrypt_3 = []
        times_encrypt_4 = []
        times_decrypt_4 = []
        for j in range(1) :
            print()
            print("ntru")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_ntru(public_key_ntru, i)
            times_encrypt_1.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_ntru(private_key_ntru, *ciphertext)
            times_decrypt_1.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            print("ecc")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_ecc(public_key_ecc, i)
            times_encrypt_2.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_ecc(private_key_ecc, ciphertext)
            times_decrypt_2.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            print("elgamal")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_elgamal(public_key_elgamal,i)
            times_encrypt_3.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_elgamal(private_key_elgamal,ciphertext)
            times_decrypt_3.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            if (num<2):
                print("rsa")
                start_time = time.time_ns()
                ciphertext = encryption.encryption_rsa(public_key_rsa ,i)
                times_encrypt_4.append((time.time_ns() - start_time)/ (10 ** 9))
                start_time = time.time_ns()
                decrypted = encryption.decryption_rsa(private_key_rsa,ciphertext)
                times_decrypt_4.append((time.time_ns() - start_time)/ (10 ** 9))
                print(i == decrypted)
            

        temp1 = sum(times_encrypt_1)/1
        temp2 = sum(times_decrypt_1)/1
        times_encrypt_ntru.append(temp1)
        times_decrypt_ntru.append(temp2)
        times_total_ntru.append(temp1+temp2)

        temp1 = sum(times_encrypt_2)/1
        temp2 = sum(times_decrypt_2)/1
        times_encrypt_ecc.append(temp1)
        times_decrypt_ecc.append(temp2)
        times_total_ecc.append(temp1+temp2)

        temp1 = sum(times_encrypt_3)/1
        temp2 = sum(times_decrypt_3)/1
        times_encrypt_elgamal.append(temp1)
        times_decrypt_elgamal.append(temp2)
        times_total_elgamal.append(temp1+temp2)
        if (num<2):
            temp1 = sum(times_encrypt_4)/1
            temp2 = sum(times_decrypt_4)/1
            times_encrypt_rsa.append(temp1)
            times_decrypt_rsa.append(temp2)
            times_total_rsa.append(temp1+temp2)
        # else : 
        #     temp1 = 0
        #     temp2 = 0
        

        times_encrypt_all = [times_encrypt_ntru,times_encrypt_ecc,times_encrypt_elgamal,times_encrypt_rsa]
        times_decrypt_all = [times_decrypt_ntru,times_decrypt_ecc,times_decrypt_elgamal,times_decrypt_rsa]
        times_total_all = [times_total_ntru,times_total_ecc,times_total_elgamal,times_total_rsa]
    


    return times_encrypt_all,times_decrypt_all,times_total_all
def analysisEncSteg (security_level):
    # algorithm = "ecc"
    # security_level = [112,128,192,256]
    # keySize_ntru = [112,128,192,256]
    # keySize_ecdsa = [224,256,384,521]
    plaintexts = []
    plaintexts.append("a"*10)
    plaintexts.append("a"*100)
    plaintexts.append("a"*1000)
    plaintexts.append("a"*10000)
    plaintexts.append("a"*100000)
    
    times_encrypt_ntru = []
    times_encrypt_ecc = []
    times_encrypt_elgamal = []
    times_encrypt_rsa = []
    times_decrypt_ntru = []
    times_decrypt_ecc = []
    times_decrypt_elgamal = []
    times_decrypt_rsa = []
    times_total_ntru = []
    times_total_ecc = []
    times_total_elgamal = []
    times_total_rsa = []
    private_key_ntru, public_key_ntru = encryption.keyGeneration_ntru(security_level)
    private_key_ecc, public_key_ecc = encryption.keyGeneration_ecc(security_level)
    private_key_elgamal, public_key_elgamal = encryption.get_key_elgamal(security_level)
    private_key_rsa, public_key_rsa = encryption.get_key_rsa(security_level)
    for num, i in enumerate(plaintexts) : 
        print(len(i))
        times_encrypt_1 = []
        times_decrypt_1 = []
        times_encrypt_2 = []
        times_decrypt_2 = []
        times_encrypt_3 = []
        times_decrypt_3 = []
        times_encrypt_4 = []
        times_decrypt_4 = []
        for j in range(1) :
            print()
            print("ntru")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_ntru(public_key_ntru, i)
            times_encrypt_1.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_ntru(private_key_ntru, *ciphertext)
            times_decrypt_1.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            print("ecc")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_ecc(public_key_ecc, i)
            times_encrypt_2.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_ecc(private_key_ecc, ciphertext)
            times_decrypt_2.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            print("elgamal")
            start_time = time.time_ns()
            ciphertext = encryption.encryption_elgamal(public_key_elgamal,i)
            times_encrypt_3.append((time.time_ns() - start_time)/ (10 ** 9))
            start_time = time.time_ns()
            decrypted = encryption.decryption_elgamal(private_key_elgamal,ciphertext)
            times_decrypt_3.append((time.time_ns() - start_time)/ (10 ** 9))
            print(i == decrypted)
            print()
            if (num<2):
                print("rsa")
                start_time = time.time_ns()
                ciphertext = encryption.encryption_rsa(public_key_rsa ,i)
                times_encrypt_4.append((time.time_ns() - start_time)/ (10 ** 9))
                start_time = time.time_ns()
                decrypted = encryption.decryption_rsa(private_key_rsa,ciphertext)
                times_decrypt_4.append((time.time_ns() - start_time)/ (10 ** 9))
                print(i == decrypted)
            

        temp1 = sum(times_encrypt_1)/1
        temp2 = sum(times_decrypt_1)/1
        times_encrypt_ntru.append(temp1)
        times_decrypt_ntru.append(temp2)
        times_total_ntru.append(temp1+temp2)

        temp1 = sum(times_encrypt_2)/1
        temp2 = sum(times_decrypt_2)/1
        times_encrypt_ecc.append(temp1)
        times_decrypt_ecc.append(temp2)
        times_total_ecc.append(temp1+temp2)

        temp1 = sum(times_encrypt_3)/1
        temp2 = sum(times_decrypt_3)/1
        times_encrypt_elgamal.append(temp1)
        times_decrypt_elgamal.append(temp2)
        times_total_elgamal.append(temp1+temp2)
        if (num<2):
            temp1 = sum(times_encrypt_4)/1
            temp2 = sum(times_decrypt_4)/1
            times_encrypt_rsa.append(temp1)
            times_decrypt_rsa.append(temp2)
            times_total_rsa.append(temp1+temp2)
        # else : 
        #     temp1 = 0
        #     temp2 = 0
        

        times_encrypt_all = [times_encrypt_ntru,times_encrypt_ecc,times_encrypt_elgamal,times_encrypt_rsa]
        times_decrypt_all = [times_decrypt_ntru,times_decrypt_ecc,times_decrypt_elgamal,times_decrypt_rsa]
        times_total_all = [times_total_ntru,times_total_ecc,times_total_elgamal,times_total_rsa]
    


    return times_encrypt_all,times_decrypt_all,times_total_all

