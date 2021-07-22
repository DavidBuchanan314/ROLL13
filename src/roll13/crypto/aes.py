"""
This AES implementation is very slow.
There are a lot of relatively simple things that could be done, to speed it
up by orders of magnitude. However, that is not the goal of this project.


"""


"""
	See section 4 of FIPS 197.
	
	Implements arithmetic over GF(2^8)
"""

# Section 4.1: Addition
# Note: this function isn't actually used anywhere, its just here for reference
def ff_add(a, b):
	return a ^ b


def ff_divmod(a, b):
	"""
		Works like "long division"
		
		https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael.27s_finite_field
		
		        11111101111110 (mod) 100011011
		       ^100011011     
		       ---------------
		        01110000011110
		        ^100011011    
		        --------------
		         0110110101110
		         ^100011011   
		         -------------
		          010101110110
		          ^100011011  
		          ------------
		           00100011010
		            ^100011011
		            ----------
		             000000001
		
		>>> ff_divmod(0b11111101111110, 0x11b)
		(61, 1)
		
	"""

	q = 0
	r = a

	while blen(r) >= blen(b): # XXX: I don't like this implementation
		q ^= 1 << (blen(r) - blen(b))
		r ^= b << (blen(r) - blen(b))

	return q, r


# Section 4.2: Multiplication
def ff_multiply(a, b, modulus=0x11b):
	# polynomial product via "long multiplication"
	# similar to calculating 132*456 as:
	# 123*6 + 1230*5 + 12300*4
	result = 0
	while b:
		result ^= a * (b & 1)
		a <<= 1
		b >>= 1

	# calculate residue
	_, r = ff_divmod(result, modulus)

	return result


# Based on extended Euclidean algorithm
def ff_multiplicative_inverse(a, modulus=0x11b):
	b = modulus
	x0, x1 = 0, 1
	while a:
		(q, a), b = ff_divmod(b, a), a
		x0, x1 = x1, x0 ^ ff_multiply(q, x1, modulus)

	_, r = ff_divmod(x0, modulus)

	return r


# Section 4.2.1: Multiplication by x
def ff_mulx(a, x):
	result = 0
	while x:
		result ^= a * (x & 1)
		a = xtime(a)
		x >>= 1

	return result


# Faster equivalent of ff_multiply(x, 2)
def xtime(x):
	x <<= 1
	if x & 0x100:
		x ^= 0x11b
	return x








"""
	See section 5 of FIPS 197.
	
	This file implements key expansion and related functions
"""

# Section 5.2: Key Expansion
def rcon(i):
	"""
		Rcon[i], contains the values given by [x^(i-1), {00}, {00} ,{00}],
		with x^(i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
		
		Although Rcon[0] is never used, I rearranged x^(i-1) to be (x^(-1))^i so that
		it can still be calculated.
		
		x^(-1) == 2^(-1) == ff_multiplicative_inverse(2) == 0x8d
		
	"""

	return [ff_mulx(0x8d, 1 << i), 0x00, 0x00, 0x00]


def rot_word(word):
	return word[1:] + word[:1]


def sub_word(word):
	return bytearray(map(sub_byte, word))


def key_expansion(key):
	"""
		Section 5.2: Key Expansion
		
		AES-128 only, for now. See Figure 11
	"""

	round_keys = [key.copy()]
	for i in range(1, 10+1):
		rkey = bytearray()
		temp = xor_bytes(sub_word(rot_word(round_keys[-1][-4:])), rcon(i))
		for j in range(4):
			temp = xor_bytes(temp, round_keys[-1][j * 4 : j * 4 + 4])
			rkey += temp
		round_keys.append(rkey)

	return round_keys











"""
	See section 5 of FIPS 197.
	
	This file implements the state tranformation functions
"""


# Section 5.1.1: SubBytes() Transformation
def sub_bytes(state):
	# apply sub_byte() to each element of the state
	# return bytearray(map(sub_byte, state))
	
	# use SBOX table lookups for better performance
	return bytearray(SBOX[s] for s in state)


def sub_byte(x):
	x = ff_multiplicative_inverse(x)

	# affine transform
	x ^= rotl(x, 1) ^ rotl(x, 2) ^ rotl(x, 3) ^ rotl(x, 4) ^ 0x63

	return x


# Section 5.1.2: ShiftRows() Transformation
def shift_rows(state):
	s2 = bytearray(4 * 4)
	for i in range(4):
		row = state[i : 4 * 4 : 4]
		s2[i : 4 * 4 : 4] = row[i:] + row[:i]
	return s2


# Section 5.1.3: MixColumns() Transformation
def mix_columns(state):
	return map_columns(mix_column, state)


def mix_column(col):
	mat_a = [[0x02, 0x03, 0x01, 0x01],
	         [0x01, 0x02, 0x03, 0x01],
	         [0x01, 0x01, 0x02, 0x03],
	         [0x03, 0x01, 0x01, 0x02]]

	# matrix multiplication
	c2 = bytearray(4)
	for y in range(4):
		for x in range(4):
			c2[y] ^= ff_mulx(col[x], mat_a[y][x])

	return c2


# Section 5.1.4: AddRoundKey() Transformation
def add_round_key(state, rkey):
	return xor_bytes(state, rkey)









# UTILS

def bitn(i, n):
	return (i >> n) & 1


def blen(n):
	return n.bit_length()


def rotl(i, n):
	return ((i << n) | (i >> 8-n)) & 0xFF


# Apply a function column-wise
def map_columns(func, state):
	s2 = bytearray()
	for i in range(4):
		s2 += func(state[i * 4 : i * 4 + 4])
	return s2


def xor_bytes(a, b):
	return bytearray([ai^bi for ai, bi in zip(a, b)])





# actual AES impl

class AES128():
	def __init__(self, key):
		self.rkeys = key_expansion(bytearray(key))

	def encrypt_block(self, _in):
		state = add_round_key(_in, self.rkeys[0])

		for i in range(1, 10):
			state = sub_bytes(state)
			state = shift_rows(state)
			state = mix_columns(state)
			state = add_round_key(state, self.rkeys[i])

		state = sub_bytes(state)
		state = shift_rows(state)
		state = add_round_key(state, self.rkeys[-1])

		return bytes(state)


# build LUT
SBOX = [sub_byte(i) for i in range(0x100)]



if __name__ == "__main__":
	TESTKEY = bytearray(range(16))
	TESTDAT = bytes.fromhex("00112233 44556677 8899aabb ccddeeff")

	aes = AES128(TESTKEY)
	print(aes.encrypt_block(TESTDAT).hex())

	from Crypto.Cipher import AES
	print(AES.new(TESTKEY, AES.MODE_ECB).encrypt(TESTDAT).hex())
