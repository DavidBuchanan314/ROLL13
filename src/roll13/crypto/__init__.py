from . import aes
from . import gcm
from . import secp256r1
from . import sha
from . import hmac
from . import hkdf


def hmac_sha256(text, key):
	return hmac.hmac(sha.sha256, 32, text, key)

def hkdf_expand_sha256(prk, info, l):
	return hkdf.hkdf_expand(sha.sha256, 32, prk, info, l)
