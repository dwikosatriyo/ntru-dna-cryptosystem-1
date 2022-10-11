import random
from convert import binstring_to_string

ProteinLib = {'A': ['GCT', 'GCC', 'GCA', 'GCG'], 'B': ['TAA', 'TAG', 'TGA'], 'C': ['TGT', 'TGC'], 'D': ['GAT', 'GAC'], 'E': ['GAA', 'GAG'], 'F': ['TTT', 'TTC'], 'G': ['GGT', 'GGC', 'GGA', 'GGG'], 'H': ['CAT', 'CAC'], 'I': ['ATT', 'ATC', 'ATA'], 'K': ['AAA', 'AAG'], 'L': ['TTA', 'TTG', 'CTT', 'CTC', 'CTA', 'CTG'], 'M': ['ATG'], 'N': ['AAT', 'AAC'], 'O': ['TTA', 'TTG'], 'P': ['CCT', 'CCC', 'CCA', 'CCG'], 'Q': ['CAA', 'CAG'], 'R': ['CGT', 'CGC', 'CGA', 'CGG', 'AGA', 'AGG'], 'S': ['TCT', 'TCC', 'TCA', 'TCG', 'AGT', 'AGC'], 'T': ['ACT', 'ACC', 'ACA', 'ACG'], 'U': ['AGA', 'AGG'], 'V': ['GTT', 'GTC', 'GTA', 'GTG'], 'W': ['TGG'], 'X': ['AGT', 'AGC'], 'Y': ['TAT', 'TAC'], 'Z': ['TAC']}
DNALib = {'GCT': ['A'], 'GCC': ['A'], 'GCA': ['A'], 'GCG': ['A'], 'TAA': ['B'], 'TAG': ['B'], 'TGA': ['B'], 'TGT': ['C'], 'TGC': ['C'], 'GAT': ['D'], 'GAC': ['D'], 'GAA': ['E'], 'GAG': ['E'], 'TTT': ['F'], 'TTC': ['F'], 'GGT':
['G'], 'GGC': ['G'], 'GGA': ['G'], 'GGG': ['G'], 'CAT': ['H'], 'CAC': ['H'], 'ATT': ['I'], 'ATC': ['I'], 'ATA': ['I'], 'AAA': ['K'], 'AAG': ['K'], 'TTA': ['L', 'O'], 'TTG': ['L', 'O'], 'CTT': ['L'], 'CTC': ['L'], 'CTA': ['L'], 'CTG': ['L'], 'ATG': ['M'], 'AAT': ['N'], 'AAC': ['N'], 'CCT': ['P'], 'CCC': ['P'], 'CCA': ['P'], 'CCG': ['P'], 'CAA': ['Q'], 'CAG': ['Q'], 'CGT': ['R'], 'CGC': ['R'], 'CGA': ['R'], 'CGG': ['R'], 'AGA': ['R',
'U'], 'AGG': ['R', 'U'], 'TCT': ['S'], 'TCC': ['S'], 'TCA': ['S'], 'TCG': ['S'], 'AGT': ['S', 'X'], 'AGC': ['S', 'X'], 'ACT': ['T'], 'ACC': ['T'], 'ACA': ['T'], 'ACG': ['T'], 'GTT': ['V'], 'GTC': ['V'], 'GTA': ['V'], 'GTG': ['V'], 'TGG': ['W'], 'TAT': ['Y'], 'TAC': ['Y', 'Z']}

def subtitution_embed(plaintext, reference):
    
    plaintext = plaintext.encode()
    bin_plaintext = "".join([bin(x)[2:].zfill(8) for x in plaintext])
    
    
    #menkonversi plaintext ke binary
    plaintext_length = len(bin_plaintext)
    reference_length = len(reference)
    
    
    dna_pair = {}
    dna_pair ["A"] = "C"
    dna_pair ["C"] = "G" 
    dna_pair ["G"] = "T"
    dna_pair ["T"] = "A"
    
 
    rand_number = random.sample(range(1, reference_length+1), plaintext_length)
    
    rand_number.sort()
    
    final_dna = ""
    i = 1
    
    for dna in reference:
        #print(i)
        try:
            a = rand_number.index(i)
            pn = bin_plaintext[a]
            if(pn == "1"):
                final_dna+=dna_pair[dna]
            else:
                final_dna+=dna
        except:
            c = dna_pair[dna]
            final_dna+=dna_pair[c[0]][0]
        i= i+1
    
    return final_dna


def subtitution_extract(steganograph, reference):
    # print("test")
    dna_pair = {}
    dna_pair ["A"] = "C"
    dna_pair ["C"] = "G" 
    dna_pair ["G"] = "T"
    dna_pair ["T"] = "A"
    s = len(reference)
    r = len(steganograph)
    # print ("s = " + str(s))
    # print ("r = "+ str(r))
    m = ""
    for i in range(s):
        if (steganograph[i] == reference[i]):
            m = m+("0")
        elif (steganograph[i] == dna_pair[reference[i]]):
            m = m+("1")
        
    # print(m)
    message_binary = [m[i:i+8] for i in range(0, len(m), 8)]
    message = [binstring_to_string(x) for x in message_binary]
    message = ''.join(message)


    return message


def subtitution_embed_binary(bin_plaintext, reference):
    
    
    #menkonversi plaintext ke binary
    plaintext_length = len(bin_plaintext)
    reference_length = len(reference)
    
    
    dna_pair = {}
    dna_pair ["A"] = "C"
    dna_pair ["C"] = "G" 
    dna_pair ["G"] = "T"
    dna_pair ["T"] = "A"
    
 
    rand_number = random.sample(range(1, reference_length+1), plaintext_length)
    
    rand_number.sort()
    
    final_dna = ""
    i = 1
    
    for dna in reference:
        #print(i)
        try:
            a = rand_number.index(i)
            pn = bin_plaintext[a]
            if(pn == "1"):
                final_dna+=dna_pair[dna]
            else:
                final_dna+=dna
        except:
            c = dna_pair[dna]
            final_dna+=dna_pair[c[0]][0]
        i= i+1
    
    return final_dna


def subtitution_extract_binary(steganograph, reference):
    # print("test")
    dna_pair = {}
    dna_pair ["A"] = "C"
    dna_pair ["C"] = "G" 
    dna_pair ["G"] = "T"
    dna_pair ["T"] = "A"
    s = len(reference)
    r = len(steganograph)
    # print ("s = " + str(s))
    # print ("r = "+ str(r))
    m = ""
    for i in range(s):
        if (steganograph[i] == reference[i]):
            m = m+("0")
        elif (steganograph[i] == dna_pair[reference[i]]):
            m = m+("1")
        
    # print(m)
    # message_binary = [m[i:i+7] for i in range(0, len(m), 7)]


    return m