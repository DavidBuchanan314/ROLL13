# https://datatracker.ietf.org/doc/html/rfc2104

def hmac(hashfunc, hashlen, key, text):
	if len(key) > hashlen:
		key = hashfunc(key)
	key += b"\x00" * (hashlen-len(key))
	ipad = b"\x36" * hashlen
	opad = b"\x5c" * hashlen
	in0 = bytes([k^i for k, i in zip(key, ipad)]) + text
	h0 = hashfunc(in0)
	in1 = bytes([k^i for k, i in zip(key, opad)]) + h0
	return hashfunc(in1)


if __name__ == "__main__":
	from sha import sha256
	#import hmac as reference_hmac
	
	print(hmac(sha256, 64, b"key", b"The quick brown fox jumps over the lazy dog").hex())
	print(hmac(sha256, 64, b"key"*123, b"The quick brown fox jumps over the lazy dog").hex())
	
	#print(reference_hmac.digest(b"key", b"The quick brown fox jumps over the lazy dog", "sha256").hex())
