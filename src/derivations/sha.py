from decimal import *

# https://stackoverflow.com/a/47192106/4454877
def cube_root( A): 
	d1 = Decimal(1)
	d2 = Decimal(2)
	d3 = Decimal(3)

	x0 = (A-d1)/d3
	xn = (d2 * x0 + A / Decimal(x0*x0) ) / d3

	limit = 100
	while xn != x0 and limit:
		x0 = xn
		xn = (d2 * x0 + A / Decimal(x0*x0) ) / d3
		limit -= 1

	return xn

def get_fractional_bits(n):
	n %= 1
	bits = 0
	frac = Decimal(1)
	for _ in range(32):
		bits <<= 1
		frac /= 2
		if n >= frac:
			bits |= 1
			n -= frac
	return bits

# naive implementation, only used for small numbers
def is_prime(n):
	for x in range(2, n):
		if n % x == 0:
			return False
	return True


getcontext().prec = 15 # log10(2^32) = 9.6, plus some margin

K = []
prime = 2
for i in range(64):
	x = get_fractional_bits(cube_root(Decimal(prime)))
	K.append(x)
	
	# next prime
	prime += 1
	while not is_prime(prime):
		prime += 1


# from FIPS PUB 180-4 section 4.2.2
target = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

assert(K == target) # we match!

for i in range(8):
	row = []
	for j in range(8):
		row.append(f"{K[i*8+j]:08x}")
	print(" ".join(row))
