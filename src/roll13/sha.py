"""
FIPS PUB 180-4
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

This specifies several hash functions, but we only implement SHA-256 here.

SHA-256: Block size 512 bits, Word size 32 bits, Digest size 256 bits

One pitfall to be aware of when reading the spec, is that the ^ symbol is used
to denote bitwise AND (not XOR), as defined in section 2.2.2.

"""


# Section 2.2.2
def rotr(x, n):
	return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# Section 2.2.2
def shr(x, n):
	return x >> n


# Section 4.1.2 (4.2)
def Ch(x, y, z):
	return (x & y) ^ (~x & z)


# Section 4.1.2 (4.3)
def Maj(x, y, z):
	return (x & y) ^ (x & z) ^ (y & z)


# Section 4.1.2 (4.4)
def S0(x):
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


# Section 4.1.2 (4.5)
def S1(x):
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


# Section 4.1.2 (4.6)
def s0(x):
	return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


# Section 4.1.2 (4.7)
def s1(x):
	return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


"""
Section 4.2.2 - SHA-256 Constants

"These words represent the first thirty-two bits of the fractional parts of the
cube roots of the first sixty-four prime numbers."

See derivations/sha.py for the derivation of these constants.
"""
K = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


# Section 5.1.1 - SHA-256 Padding
# Note: this is defined in terms of bit lengths, we assume the message comes in
# 8-bit bytes.
def pad_message(m):
	msg_len = len(m)
	padded_length = ((msg_len + 1 + 8 + 63) // 64) * 64
	out = m + b"\x80"  # a "1" bit, padded with zeroes until the end of the byte
	out += b"\x00" * (padded_length - len(out) - 8) # the rest of the zeroes
	out += (msg_len * 8).to_bytes(8, "big") # message length, in bits, as 64-bit int
	assert(len(out) % (512//8) == 0)
	return out


# Section 5.2.1
def block_iterator(m):
	for i in range(0, len(m), 512//8):
		yield m[i:i+512//8]


# Section 5.2.1
def word_iterator(m):
	for i in range(0, len(m), 32//8):
		yield int.from_bytes(m[i:i+32//8], "big")


# Section 5.3.3
# TODO: where do these come from?
initial_H = [
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
]


# Section 6.2
def sha256(m):
	# 6.2.1, 1) Initialize H
	H = initial_H.copy()
	
	# 6.2.1, 2) pad the message, and parse it into blocks
	blocks = block_iterator(pad_message(m))
	
	# 6.2.2 - SHA-256 Hash Computation
	for block in blocks:
		
		# 1. Prepare the message schedule
		W = list(word_iterator(block))
		for t in range(16, 64):
			W.append((s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]) & 0xFFFFFFFF)
		
		# 2. Initialize the eight working variables
		a, b, c, d, e, f, g, h = H
		
		# 3.
		for t in range(64):
			T1 = h + S1(e) + Ch(e, f, g) + K[t] + W[t]
			T2 = S0(a) + Maj(a, b, c)
			h = g
			g = f
			f = e
			e = (d + T1) & 0xFFFFFFFF
			d = c
			c = b
			b = a
			a = (T1 + T2) & 0xFFFFFFFF
		
		# 4. Calculate the next Hash value
		for i, x in enumerate((a, b, c, d, e, f, g, h)):
			H[i] = (H[i] + x) & 0xFFFFFFFF
	
	# convert the result to bytes
	M = b""
	for word in H:
		M += word.to_bytes(32//8, "big")
	return M
