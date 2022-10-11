def string_to_ascii(string):
    if not isinstance(string, bytes):
        ord_str = [ord(l) for l in string]
    else:
        ord_str = [int(x) for x in string]
    return ord_str
def ascii_to_binary(input):
    bin_str = "".join([bin(x)[2:].zfill(8) for x in input])
    return bin_str
def string_to_binary(string):
    if not isinstance(string, bytes):
        ord_str = [ord(l) for l in string]
    else:
        ord_str = [int(x) for x in string]
    bin_str = "".join([bin(x)[2:].zfill(8) for x in ord_str])
    #[2:].zfill(8) untuk menghilangkan 0b
    return bin_str
def binary_to_string(binary):
    c = int(binary, base =2)
    string = c.to_bytes((c.bit_length() + 7) // 8, 'big').decode()
    return string
def binary_to_DNA (binary):
    binary = str(binary)
    seq = ""
    seqarray = []
    for i, j in zip(binary[::2], binary[1::2]):
    # for i in [binary[i:i+2] for i in range(0, len(binary), 2)] <= sama
        if i+j == '00':
            # seq=seq+'A'
            seqarray.append('A')
        elif i+j == '01':
            # seq=seq+'C'
            seqarray.append('C') 
        elif i+j == '10':
            # seq=seq+'G'
            seqarray.append('G') 
        elif i+j == '11':
            # seq=seq+'U'
            seqarray.append('T')
    seq = "".join(seqarray)
    return seq
def binary_to_DNA_ntru (binary):
    binary = str(binary)
    seq = ""
    seqarray = []
    for i, j in zip(binary[::2], binary[1::2]):
    # for i in [binary[i:i+2] for i in range(0, len(binary), 2)] <= sama
        if i+j == '00':
            # seq=seq+'A'
            seqarray.append(-2)
        elif i+j == '01':
            # seq=seq+'C'
            seqarray.append(-1) 
        elif i+j == '10':
            # seq=seq+'G'
            seqarray.append(0) 
        elif i+j == '11':
            # seq=seq+'U'
            seqarray.append(1)
    seq = "".join(seqarray)
    return seq
def DNA_to_binary (seq):
    binary = ""
    binaryarray = []
    for i in seq:
        if  i == 'A':
            # binary=binary+'00'
            binaryarray.append('00')
        elif i == 'C':
            # binary=binary+'01'
            binaryarray.append('01')
        elif i == 'G':
            # binary=binary+'10' 
            binaryarray.append('10')
        elif i == 'T':
            # binary=binary+'11'
            binaryarray.append('11')
    binary = "".join(binaryarray)
    return binary
def string_to_DNA (string):
    binary = string_to_binary(string)
    dna = binary_to_DNA (binary)
    return dna
def DNA_to_string (dna):
    binary = DNA_to_binary (dna)
    string = binary_to_string(binary)
    return string
    