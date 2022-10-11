import sys, os
sys.path.append(os.path.abspath(os.path.join('app','process','cryptography','ntruEnc','ntru')))
from ntrucipher import NtruCipher


N = 167
p = 3
q = 128
ntru = NtruCipher(N, p, q)
ntru.generate_random_keys()
