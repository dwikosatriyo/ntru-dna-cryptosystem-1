from asyncio.windows_events import NULL
from time import time
from app.process import normal, dna, test, dnaCrypt, test_analysis
def encNormal (parameter,algorithm):
   if algorithm == "ntru":
      # result = normal.encNtru(parameter["plaintext"], parameter["N"], parameter["p"], parameter["q"], parameter["f"], parameter["g"], parameter["d"], parameter["randPol"])
      result = normal.encNtru(parameter[6], parameter[0], parameter[1], parameter[2], parameter[3], parameter[4], parameter[5],  parameter[7])
    # elif method == "rsa":

    # elif method == "elGamal":

   elif algorithm == "ecc":
      result = normal.encECC(parameter[1], int(parameter[0]))
   elif algorithm == "elGamal":
      result = normal.encElGamal(parameter[1], int(parameter[0]))
   elif algorithm == "rsa":
      result = normal.encRSA(parameter[1], int(parameter[0]))
   return result
def encDNA (parameter,algorithm):
   if algorithm == "ntru":
      input_len = len(parameter)-2
   else :
      input_len = len(parameter)-1
   parameter.append(dna.string_to_DNA(parameter[input_len]))
   if algorithm == "ntru":
      # result = normal.encNtru(parameter["plaintext"], parameter["N"], parameter["p"], parameter["q"], parameter["f"], parameter["g"], parameter["d"], parameter["randPol"])
      result = normal.encNtru(parameter[8], parameter[0], parameter[1], parameter[2], parameter[3], parameter[4], parameter[5],  parameter[7])
    # elif method == "rsa":

    # elif method == "elGamal":

   elif algorithm == "ecc":
      result = normal.encECC(parameter[2], int(parameter[0]))
   elif algorithm == "elGamal":
      result = normal.encElGamal(parameter[2], int(parameter[0]))
   elif algorithm == "rsa":
      result = normal.encRSA(parameter[2], int(parameter[0]))
   result_length = len(result)-1
   result.append(dna.DNA_to_string(result[result_length]))
   return result

def testEncNormal (parameter,algorithm):
   times = []
   times.append(test.encNtruTime(parameter[1],int(parameter[0])))
   times.append(test.encECCTime(parameter[1],int(parameter[0])))
   times.append(test.encElGamalTime(parameter[1],int(parameter[0])))
   times.append(test.encRSATime(parameter[1],int(parameter[0])))
   keyGeneration_times = []
   encryption_times = []
   decryption_times = []
   total_times = []
   for i in times :
      keyGeneration_times.append(i[0])
      encryption_times.append(i[1])
      decryption_times.append(i[2])
      total_times.append(i[3])
   result = [keyGeneration_times,encryption_times,decryption_times,total_times]
   return result

def testEncDNA(parameter,algorithm):
   input_len = len(parameter)-1
   parameter.append(dna.string_to_DNA(parameter[input_len]))
   times = []
   times.append(test.encNtruTime(parameter[2],int(parameter[0])))
   times.append(test.encECCTime(parameter[2],int(parameter[0])))
   times.append(test.encElGamalTime(parameter[2],int(parameter[0])))
   times.append(test.encRSATime(parameter[2],int(parameter[0])))
   keyGeneration_times = []
   encryption_times = []
   decryption_times = []
   total_times = []
   for i in times :
      keyGeneration_times.append(i[0])
      encryption_times.append(i[1])
      decryption_times.append(i[2])
      total_times.append(i[3])
   result = [keyGeneration_times,encryption_times,decryption_times,total_times]
   return result

def testEncAnalysis(parameter):
    if parameter[0] == "112" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(112)
    elif parameter[0] == "128" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(128)
    elif parameter[0] == "192" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(192)
    elif parameter[0] == "256" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(256)
    elif parameter[0] == "all" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(112)
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(128)
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(192)
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEnc(256)
    result = [times_encrypt,times_decrypt,times_total]

    return result
   
def testEncDnaAnalysis(parameter):
    if parameter[0] == "112" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(112)
    elif parameter[0] == "128" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(128)
    elif parameter[0] == "192" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(192)
    elif parameter[0] == "256" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(256)
    elif parameter[0] == "all" :
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(112)
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(128)
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(192)
        times_encrypt,times_decrypt,times_total = test_analysis.analysisEncDna(256)
    result = (times_encrypt,times_decrypt,times_total)
    return result
    
def testdnaCrypt(parameter,algorithm) :
   # all.dnaCryptTime(securityLevel, encryption_method, plaintext, dna_cover)
   times = dnaCrypt.dnaCryptTime(parameter[0], parameter[1], parameter[2])
   keyGeneration_times = []
   encryption_times = []
   embedding_times = []
   extracting_times = []
   decryption_times = []
   total_times = []
   # print(times)
   for i in times :
      keyGeneration_times.append(i[0])
      encryption_times.append(i[1])
      embedding_times.append(i[2])
      extracting_times.append(i[3])
      decryption_times.append(i[4])
      total_times.append(i[5])
   result = [keyGeneration_times,encryption_times,embedding_times,extracting_times, decryption_times,total_times]
   return result
