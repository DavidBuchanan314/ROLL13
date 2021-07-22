"""

NIST SP 800-38D
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

One big pitfall to be aware of, is that this spec uses a "little endian"
representation of polynomial bit strings (See section 6.3)

"""


# Section 6.3 - Multiplication Operation on Blocks
def block_multiply(X, Y):
	R = 0b_1110_0001 << 120
	
	Z = 0
	V = Y
	
	for i in range(128):
		if (X >> (127-i)) & 1:  # Confusingly, the MSB is bit 0
			Z ^= V
		if V & 1:
			V = (V >> 1) ^ R
		else:
			V >>= 1
	
	return Z


# Section 6.4 - GHASH function
def GHASH(H, X):
	Y = 0
	for i in range(0, len(X), 16):
		Xi = int.from_bytes(X[i:i+16], "big")
		Y = block_multiply(Y ^ Xi, H)
	return Y


# increment the last 32 bits of a block
def inc32(block):
	start, end = block[:-4], block[-4:]
	n = int.from_bytes(end, "big")
	return start + ((n + 1) & 0xFFFFFFFF).to_bytes(4, "big")


# Section 6.5 - GCTR Function
def GCTR(ICB, X, CIPHk):
	CBi = ICB
	Y = []
	for i in range(0, len(X), 16):
		Xi = X[i:i+16]
		CBenc = CIPHk(CBi)
		CBi = inc32(CBi)
		for a, b in zip(CBenc, Xi):
			Y.append(a^b)
	return bytes(Y)


# Section 7.1 - Algorithm for the Authenticated Encryption Function
def gcm_ae(IV, P, A, CIPHk):
	H = int.from_bytes(CIPHk(bytes(16)), "big")
	assert(len(IV) == 12) # TODO: support other lengths?
	J0 = IV + b"\x00\x00\x00\x01"
	C = GCTR(inc32(J0), P, CIPHk)
	
	u = (-len(C)) % 16
	v = (-len(A)) % 16
	
	tmp = A + bytes(v) + C + bytes(u)
	tmp += (len(A)*8).to_bytes(8, "big")
	tmp += (len(C)*8).to_bytes(8, "big")
	S = GHASH(H, tmp).to_bytes(16, "big")
	
	T = GCTR(J0, S, CIPHk) # TODO: support other tag lengths?
	return C, T


# Section 7.2 - Algorithm for the Authenticated Decryption Function
def gcm_ad(IV, C, A, T, CIPHk):
	assert(len(T) == 16)
	H = int.from_bytes(CIPHk(bytes(16)), "big")
	assert(len(IV) == 12)
	J0 = IV + b"\x00\x00\x00\x01"
	P = GCTR(inc32(J0), C, CIPHk)
	
	u = (-len(C)) % 16
	v = (-len(A)) % 16
	
	tmp = A + bytes(v) + C + bytes(u)
	tmp += (len(A)*8).to_bytes(8, "big")
	tmp += (len(C)*8).to_bytes(8, "big")
	S = GHASH(H, tmp).to_bytes(16, "big")
	
	Tcalc = GCTR(J0, S, CIPHk)
	assert(Tcalc == T) # bad auth tag
	return P


if __name__ == "__main__":
	from aes import AES128 # lets use our own AES, where possible
	from Crypto.Cipher import AES
	
	pt = b"The quick brown fox jumps over the lazy dog"
	nonce = b"0123456789ab"
	key = b"VERY_SECURE_KEY_"

	#CIPHk = AES.new(mode=AES.MODE_ECB, key=bytes(16)).encrypt
	CIPHk = AES128(key).encrypt_block

	c, t = gcm_ae(IV=nonce, P=pt, A=b"foobar", CIPHk=CIPHk)
	
	print("gcm_ae:")
	print(c.hex())
	print("tag:")
	print(t.hex())



	aes = AES.new(mode=AES.MODE_GCM, key=key, nonce=nonce)

	aes.update(b"foobar")
	ct, tag = aes.encrypt_and_digest(pt)
	print()
	print("pycrypto pt:")
	print(ct.hex())
	print("pycrypto tag:")
	print(tag.hex())

	assert(c == ct)
	assert(t == tag)
	
	out = gcm_ad(IV=nonce, C=c, A=b"foobar", T=t, CIPHk=CIPHk)
	print()
	print("out:")
	print(out)
