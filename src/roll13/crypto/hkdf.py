from .hmac import hmac

# https://datatracker.ietf.org/doc/html/rfc5869

def hkdf_extract(hashfunc, hashlen, salt, ikm):
	if salt is None:
		salt = bytes(hashlen)
	
	return hmac(hashfunc, 64, salt, ikm) # XXX 64


def hkdf_expand(hashfunc, hashlen, prk, info, l):
	assert(len(prk) >= hashlen)
	assert(l <= 255 * hashlen)
	
	prev = b""
	T = b""
	for i in range(0, l, hashlen):
		tmp = prev + info + (i//hashlen+1).to_bytes(1, "big")
		prev = hmac(hashfunc, 64, prk, tmp)# XXX don't hardcode 64
		T += prev
	
	return T[:l]


def hkdf_expand_label(hashfunc, hashlen, secret, label, context, length):
	hkdf_label = b""
	hkdf_label += length.to_bytes(2, "big")
	label_str = b"tls13 " + label
	hkdf_label += len(label_str).to_bytes(1, "big")
	hkdf_label += label_str
	hkdf_label += len(context).to_bytes(1, "big")
	hkdf_label += context
	
	return hkdf_expand(hashfunc, hashlen, secret, hkdf_label, length)


if __name__ == "__main__":
	from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
	from cryptography.hazmat.primitives import serialization, hashes
	from sha import sha256
	
	print(HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"A"*32).derive(b"A"*32).hex())
	print(hkdf_expand(sha256, 32, b"A"*32, b"A"*32, 32).hex())
