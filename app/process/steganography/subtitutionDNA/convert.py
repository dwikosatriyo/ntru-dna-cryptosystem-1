

def binstring_to_string(binary):
    c = int(binary, base =2)
    string = c.to_bytes((c.bit_length() + 8) // 9, 'big').decode()
    return string