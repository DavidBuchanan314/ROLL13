import roll13
import socket
from ctypes import *
import os
import io
from enum import IntEnum
from roll13.utils import *

class CipherSuite(IntEnum):
	TLS_AES_128_GCM_SHA256       = 0x1301
	TLS_AES_256_GCM_SHA384       = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303
	TLS_AES_128_CCM_SHA256       = 0x1304
	TLS_AES_128_CCM_8_SHA256     = 0x1305


class HandshakeType(IntEnum):
	client_hello         = 1
	server_hello         = 2
	new_session_ticket   = 4
	end_of_early_data    = 5
	encrypted_extensions = 8
	certificate          = 11
	certificate_request  = 13
	certificate_verify   = 15
	finished             = 20
	key_update           = 24
	message_hash         = 254


class AlertLevel(IntEnum):
	warning = 1
	fatal   = 2


class AlertDescription(IntEnum):
	close_notify                    = 0
	unexpected_message              = 10
	bad_record_mac                  = 20
	record_overflow                 = 22
	handshake_failure               = 40
	bad_certificate                 = 42
	unsupported_certificate         = 43
	certificate_revoked             = 44
	certificate_expired             = 45
	certificate_unknown             = 46
	illegal_parameter               = 47
	unknown_ca                      = 48
	access_denied                   = 49
	decode_error                    = 50
	decrypt_error                   = 51
	protocol_version                = 70
	insufficient_security           = 71
	internal_error                  = 80
	inappropriate_fallback          = 86
	user_canceled                   = 90
	missing_extension               = 109
	unsupported_extension           = 110
	unrecognized_name               = 112
	bad_certificate_status_response = 113
	unknown_psk_identity            = 115
	certificate_required            = 116
	no_application_protocol         = 120


class Alert(PrettyPrintable):
	def __init__(self, level, description):
		self.level = level
		self.description = description
	
	@classmethod
	def read_from(cls, sf):
		return cls(
			level=AlertLevel(int.from_bytes(sf.read(1), "big")),
			description=AlertDescription(int.from_bytes(sf.read(1), "big"))
		)


class Handshake(PrettyPrintable):
	def __init__(self, msg_type, msg):
		self.msg_type = msg_type
		self.msg = msg
	
	@classmethod
	def read_from(cls, sf):
		msg_type = HandshakeType(int.from_bytes(sf.read(1), "big"))
		length = int.from_bytes(sf.read(3), "big")
		msg = sf.read(length)
		
		if msg_type == HandshakeType.client_hello:
			msg = ClientHello.read_from(io.BytesIO(msg))
		elif msg_type == HandshakeType.server_hello:
			msg = ServerHello.read_from(io.BytesIO(msg))
		elif msg_type == HandshakeType.encrypted_extensions:
			msg = EncryptedExtensions.read_from(io.BytesIO(msg))
		elif msg_type == HandshakeType.certificate:
			msg = Certificate.read_from(io.BytesIO(msg))
		
		return cls(msg_type, msg)


class ClientHello(PrettyPrintable):
	def __init__(self,
		legacy_version,
		random,
		legacy_session_id,
		cipher_suites,
		legacy_compression_methods,
		extensions
	):
		self.legacy_version = legacy_version
		self.random = random
		self.legacy_session_id = legacy_session_id
		self.cipher_suites = cipher_suites
		self.legacy_compression_methods = legacy_compression_methods
		self.extensions = extensions
	
	@classmethod
	def read_from(cls, sf):
		legacy_version = int.from_bytes(sf.read(2), "big")
		random = sf.read(32)
		legacy_session_id_len = int.from_bytes(sf.read(1), "big")
		legacy_session_id = sf.read(legacy_session_id_len)
		cipher_suites_len = int.from_bytes(sf.read(2), "big")
		cipher_suites = []
		for _ in range(cipher_suites_len // 2):
			cipher_suites.append(CipherSuite(int.from_bytes(sf.read(2), "big")))
		legacy_compression_methods = sf.read(2)
		extensions_len = int.from_bytes(sf.read(2), "big")
		extensions = read_extension_list(io.BytesIO(sf.read(extensions_len)), context=HandshakeType.client_hello)
		return cls(
			legacy_version,
			random,
			legacy_session_id,
			cipher_suites,
			legacy_compression_methods,
			extensions
		)


class ServerHello(PrettyPrintable):
	def __init__(self,
		legacy_version,
		random,
		legacy_session_id_echo,
		cipher_suite,
		legacy_compression_method,
		extensions
	):
		self.legacy_version = legacy_version
		self.random = random
		self.legacy_session_id_echo = legacy_session_id_echo
		self.legacy_compression_method = legacy_compression_method
		self.extensions = extensions
	
	@classmethod
	def read_from(cls, sf):
		legacy_version = int.from_bytes(sf.read(2), "big")
		random = sf.read(32)
		legacy_session_id_echo_len = int.from_bytes(sf.read(1), "big")
		legacy_session_id_echo = sf.read(legacy_session_id_echo_len)
		cipher_suite = CipherSuite(int.from_bytes(sf.read(2), "big"))
		legacy_compression_method = int.from_bytes(sf.read(1), "big")
		extensions_len = int.from_bytes(sf.read(2), "big")
		extensions = read_extension_list(io.BytesIO(sf.read(extensions_len)), context=HandshakeType.server_hello)
		# TODO: parse extensions
		return cls(
			legacy_version=legacy_version,
			random=random,
			legacy_session_id_echo=legacy_session_id_echo,
			cipher_suite=cipher_suite,
			legacy_compression_method=legacy_compression_method,
			extensions=extensions
		)

class EncryptedExtensions(PrettyPrintable):
	def __init__(self, extensions):
		self.extensions = extensions
	
	@classmethod
	def read_from(cls, sf):
		extensions_len = int.from_bytes(sf.read(2), "big")
		extensions = read_extension_list(io.BytesIO(sf.read(extensions_len)), context=HandshakeType.encrypted_extensions)
		return cls(extensions)


class Certificate(PrettyPrintable):
	def __init__(self, certificate_request_context, certificate_list):
		self.certificate_request_context = certificate_request_context
		self.certificate_list = certificate_list
	
	@classmethod
	def read_from(cls, sf):
		context_len = int.from_bytes(sf.read(1), "big")
		certificate_request_context = sf.read(context_len)
		cert_list_len = int.from_bytes(sf.read(3), "big")
		certificate_list = []
		start = sf.tell()
		while sf.tell() - start < cert_list_len:
			certificate_list.append(CertificateEntry.read_from(sf))
		
		return cls(certificate_request_context, certificate_list)


class CertificateEntry(PrettyPrintable):
	# XXX: assume always x509
	def __init__(self, cert_data, extensions):
		self.cert_data = cert_data
		self.extensions = extensions
	
	@classmethod
	def read_from(cls, sf):
		cert_len = int.from_bytes(sf.read(3), "big")
		cert_data = sf.read(cert_len)
		extensions_len = int.from_bytes(sf.read(2), "big")
		extensions = read_extension_list(io.BytesIO(sf.read(extensions_len)), context="dunno")
		return cls(cert_data, extensions)


class ExtensionType(IntEnum):
	server_name                            = 0
	max_fragment_length                    = 1
	status_request                         = 5
	supported_groups                       = 10
	signature_algorithms                   = 13
	use_srtp                               = 14
	heartbeat                              = 15
	application_layer_protocol_negotiation = 16
	signed_certificate_timestamp           = 18
	client_certificate_type                = 19
	server_certificate_type                = 20
	padding                                = 21
	RESERVED_40                            = 40
	pre_shared_key                         = 41
	early_data                             = 42
	supported_versions                     = 43
	cookie                                 = 44
	psk_key_exchange_modes                 = 45
	RESERVED_46                            = 46
	certificate_authorities                = 47
	oid_filters                            = 48
	post_handshake_auth                    = 49
	signature_algorithms_cert              = 50
	key_share                              = 51


def read_extension_list(bio, **kwargs):
	assert(type(bio) is io.BytesIO)
	res = []
	while bio.tell() < bio.getbuffer().nbytes:
		res.append(Extension.read_from(bio, **kwargs))
	return res


class Extension(PrettyPrintable):
	def __init__(self, extension_type, extension_data):
		self.extension_type = extension_type
		self.extension_data = extension_data
	
	@classmethod
	def read_from(cls, sf, context):
		extension_type = ExtensionType(int.from_bytes(sf.read(2), "big"))
		data_len = int.from_bytes(sf.read(2), "big")
		extension_data = sf.read(data_len)
		
		if extension_type == ExtensionType.key_share:
			if context == HandshakeType.server_hello:
				extension_data = KeyShareServerHello.read_from(io.BytesIO(extension_data))
			elif context == HandshakeType.client_hello:
				extension_data = KeyShareClientHello.read_from(io.BytesIO(extension_data))
			else:
				assert(False)
		elif extension_type == ExtensionType.supported_groups:
			extension_data = NamedGroupList.read_from(io.BytesIO(extension_data))
		
		return cls(extension_type, extension_data)


class NamedGroupList(PrettyPrintable):
	def __init__(self, named_group_list):
		self.named_group_list = named_group_list
	
	@classmethod
	def read_from(cls, sf):
		count = int.from_bytes(sf.read(2), "big") // 2
		named_group_list = []
		for _ in range(count):
			named_group_list.append(NamedGroup(int.from_bytes(sf.read(2), "big")))
		return cls(named_group_list)


class KeyShareServerHello(PrettyPrintable):
	def __init__(self, server_share):
		self.server_share = server_share
	
	@classmethod
	def read_from(cls, sf):
		server_share = KeyShareEntry.read_from(sf)
		return cls(server_share)


class KeyShareClientHello(PrettyPrintable):
	def __init__(self, client_shares):
		self.client_shares = client_shares
	
	@classmethod
	def read_from(cls, bio):
		assert(type(bio) == io.BytesIO)
		assert(bio.tell() == 0)
		client_shares_len = int.from_bytes(bio.read(2), "big")
		client_shares = []
		while bio.tell() - 2 < client_shares_len:
			client_shares.append(KeyShareEntry.read_from(bio))
		return cls(client_shares)


class KeyShareEntry(PrettyPrintable):
	def __init__(self, group, key_exchange):
		self.group = group
		self.key_exchange = key_exchange
	
	@classmethod
	def read_from(cls, sf):
		group = NamedGroup(int.from_bytes(sf.read(2), "big"))
		key_exchange_len = int.from_bytes(sf.read(2), "big")
		key_exchange = sf.read(key_exchange_len)
		
		if group == NamedGroup.secp256r1:
			key_exchange = UncompressedPointRepresentation.read_from(io.BytesIO(key_exchange), 32)
		
		return cls(group, key_exchange)


class UncompressedPointRepresentation(PrettyPrintable):
	def __init__(self, legacy_form, X, Y):
		self.legacy_form = 4
		self.X = X
		self.Y = Y
	
	@classmethod
	def read_from(cls, sf, coordinate_length):
		legacy_form = int.from_bytes(sf.read(1), "big")
		X = sf.read(coordinate_length)
		Y = sf.read(coordinate_length)
		return cls(legacy_form, X, Y)


class SignatureScheme(IntEnum):
	# RSASSA-PKCS1-v1_5 algorithms
	rsa_pkcs1_sha256 = 0x0401
	rsa_pkcs1_sha384 = 0x0501
	rsa_pkcs1_sha512 = 0x0601

	# ECDSA algorithms
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	ecdsa_secp521r1_sha512 = 0x0603

	# RSASSA-PSS algorithms with public key OID rsaEncryption
	rsa_pss_rsae_sha256 = 0x0804
	rsa_pss_rsae_sha384 = 0x0805
	rsa_pss_rsae_sha512 = 0x0806

	# EdDSA algorithms
	ed25519 = 0x0807
	ed448   = 0x0808

	# RSASSA-PSS algorithms with public key OID RSASSA-PSS
	rsa_pss_pss_sha256 = 0x0809
	rsa_pss_pss_sha384 = 0x080a
	rsa_pss_pss_sha512 = 0x080b

	# Legacy algorithms
	rsa_pkcs1_sha1 = 0x0201
	ecdsa_sha1     = 0x0203


class NamedGroup(IntEnum):
	# Elliptic Curve Groups (ECDHE)
	secp256r1 = 0x0017
	secp384r1 = 0x0018
	secp521r1 = 0x0019
	x25519    = 0x001D
	x448      = 0x001E

	# Finite Field Groups (DHE)
	ffdhe2048 = 0x0100
	ffdhe3072 = 0x0101
	ffdhe4096 = 0x0102
	ffdhe6144 = 0x0103
	ffdhe8192 = 0x0104


# 5.1 RECORD LAYER

class ContentType(IntEnum):
	invalid = 0
	change_cipher_spec = 20
	alert = 21
	handshake = 22
	application_data = 23


class TLSPlaintext(PrettyPrintable):
	def __init__(self,
		type_,
		legacy_record_version,
		fragment
	):
		self.type = type_
		self.legacy_record_version = legacy_record_version
		self.fragment = fragment
	
#	def __repr__(self):
#		return f"<TLSPlaintext(type={self.type!r}, \
#legacy_record_version={hex(self.legacy_record_version)}, \
#length={len(self.fragment)}, \
#fragment={self.fragment})>"
	
	@classmethod
	def read_from(cls, sf):
		type_ = ContentType(int.from_bytes(sf.read(1), "big"))
		legacy_record_version = int.from_bytes(sf.read(2), "big")
		length = int.from_bytes(sf.read(2), "big")
		
		fragment_buf = io.BytesIO(sf.read(length))
		
		if type_ == ContentType.alert:
			fragment = Alert.read_from(fragment_buf)
		elif type_ == ContentType.handshake:
			fragment = Handshake.read_from(fragment_buf)
		else:
			# TODO: error
			fragment = fragment_buf.read(length)
		
		# TODO: check if we actually read the correct length
		
		c = cls(
			type_=type_,
			legacy_record_version=legacy_record_version,
			fragment=fragment
		)
		
		c.fragment_opaque = fragment_buf
		
		return c
	
	def write_to(self, sf):
		sf.write(int(self.type).to_bytes(1, "big"))
		sf.write(self.legacy_record_version.to_bytes(2, "big"))
		sf.write(len(self.fragment).to_bytes(2, "big"))
		sf.write(self.fragment)
		sf.flush()


class TLSCiphertext(PrettyPrintable):
	def __init__(self,
		opaque_type,
		legacy_record_version,
		length,
		encrypted_record
	):
		pass # TODO


# END RECORD LAYER


hello = b""

legacy_version = 0x0303 # TLS v1.2
hello += legacy_version.to_bytes(2, "big")

random = os.urandom(32)
hello += random

legacy_session_id = os.urandom(32)
hello += len(legacy_session_id).to_bytes(1, "big")
hello += legacy_session_id

cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
hello += len(cipher_suites * 2).to_bytes(2, "big")
for c in cipher_suites:
	hello += c.to_bytes(2, "big")

legacy_compression_methods = b"\x01\x00"
hello += legacy_compression_methods


# sig algs packing

def pack_22(sigalgs):
	res = len(sigalgs * 2).to_bytes(2, "big")
	for alg in sigalgs:
		res += int(alg).to_bytes(2, "big")
	return res

sas = pack_22([
	SignatureScheme.rsa_pkcs1_sha256,
	#SignatureScheme.rsa_pkcs1_sha384,
	#SignatureScheme.rsa_pkcs1_sha512,
	
	SignatureScheme.ecdsa_secp256r1_sha256,
	#SignatureScheme.ecdsa_secp384r1_sha384,
	#SignatureScheme.ecdsa_secp521r1_sha512,
	
	SignatureScheme.rsa_pss_rsae_sha256,
	#SignatureScheme.rsa_pss_rsae_sha384,
	#SignatureScheme.rsa_pss_rsae_sha512,
	
	#SignatureScheme.ed25519,
	#SignatureScheme.ed448,
	
	#SignatureScheme.rsa_pss_pss_sha256,
	#SignatureScheme.rsa_pss_pss_sha384,
	#SignatureScheme.rsa_pss_pss_sha512,
])

sa = pack_22([
	#SignatureScheme.rsa_pkcs1_sha256,
	#SignatureScheme.rsa_pkcs1_sha384,
	#SignatureScheme.rsa_pkcs1_sha512,
	
	SignatureScheme.ecdsa_secp256r1_sha256,
	#SignatureScheme.ecdsa_secp384r1_sha384,
	#SignatureScheme.ecdsa_secp521r1_sha512,
	
	SignatureScheme.rsa_pss_rsae_sha256, # Required for CertificateVerify
	#SignatureScheme.rsa_pss_rsae_sha384,
	#SignatureScheme.rsa_pss_rsae_sha512,
	
	#SignatureScheme.ed25519,
	#SignatureScheme.ed448,
	
	#SignatureScheme.rsa_pss_pss_sha256,
	#SignatureScheme.rsa_pss_pss_sha384,
	#SignatureScheme.rsa_pss_pss_sha512,
])


point = roll13.crypto.secp256r1.G * 1337

keyshare = int(NamedGroup.secp256r1).to_bytes(2, "big")
keyshare += (65).to_bytes(2, "big")
keyshare += b"\x04"
keyshare += point.x.to_bytes(32, "big")
keyshare += point.y.to_bytes(32, "big")

# NOTE: Section 9.2 Mandatory-to-Implement Extensions

server_name = b"\x00\x00\x18www.da.vidbuchanan.co.uk"
extensions = [
	(ExtensionType.server_name, len(server_name).to_bytes(2, "big") + server_name),
	(ExtensionType.supported_versions, b"\x02\x03\x04"),
	(ExtensionType.signature_algorithms_cert, sas),
	(ExtensionType.signature_algorithms, sa),
	(ExtensionType.supported_groups, pack_22([NamedGroup.secp256r1])),
	(ExtensionType.key_share, len(keyshare).to_bytes(2, "big") + keyshare),
]

ext_bytes = b""
for e_type, e_data in extensions:
	ext_bytes += int(e_type).to_bytes(2, "big")
	ext_bytes += len(e_data).to_bytes(2, "big")
	ext_bytes += e_data

hello += len(ext_bytes).to_bytes(2, "big")
hello += ext_bytes


# Handshake struct
foo = int(HandshakeType.client_hello).to_bytes(1, "big")
foo += len(hello).to_bytes(3, "big")
foo += hello




sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("www.da.vidbuchanan.co.uk", 443))
#sock.connect(("localhost", 1234))
sf = sock.makefile("rwb")

record = TLSPlaintext(ContentType.handshake, 0x0301, foo)
bio = io.BytesIO()
record.write_to(bio)
record.write_to(sf)

print("SENDING:")
print(record)
print(TLSPlaintext.read_from(io.BytesIO(bio.getbuffer())))

server_hello = TLSPlaintext.read_from(sf)
print("RECEIVING:")
print(server_hello)


res_extensions = server_hello.fragment.msg.extensions
keyshare = [e.extension_data for e in res_extensions if e.extension_type == ExtensionType.key_share][0]
server_point = keyshare.server_share.key_exchange
server_dh = roll13.crypto.secp256r1.Point(
	int.from_bytes(server_point.X, "big"),
	int.from_bytes(server_point.Y, "big")
)

dh_secret = (server_dh * 1337).x.to_bytes(32, "big")

print("dh secret:", dh_secret.hex())

transcript_hash_buf = foo + server_hello.fragment_opaque.getbuffer()
transcript_hash = roll13.crypto.sha.sha256(transcript_hash_buf)

print("transcript_hash:", transcript_hash.hex())

"""
Derive-Secret(Secret, Label, Messages) =
            HKDF-Expand-Label(Secret, Label,
                              Transcript-Hash(Messages), Hash.length)
"""

def derive_secret(secret, label, transcript_hash):
	return roll13.crypto.hkdf.hkdf_expand_label(roll13.crypto.sha.sha256, 32, secret, label, transcript_hash, 32)

def extract_secret(secret):
	return roll13.crypto.hkdf.hkdf_extract(roll13.crypto.sha.sha256, 32, b"\x00"*32, secret)


early_secret = extract_secret(b"\x00"*32)
print("early_secret:", early_secret.hex())
derived_secret = derive_secret(early_secret, b"derived", roll13.crypto.sha.sha256(b""))
print("derived_secret:", derived_secret.hex())
handshake_secret =  roll13.crypto.hkdf.hkdf_extract(roll13.crypto.sha.sha256, 32, derived_secret, dh_secret)
print("handshake_secret:", handshake_secret.hex())


client_handshake_traffic_secret = derive_secret(handshake_secret, b"c hs traffic", transcript_hash)
print("client_handshake_traffic_secret:", client_handshake_traffic_secret.hex())
server_handshake_traffic_secret = derive_secret(handshake_secret, b"s hs traffic", transcript_hash)
print("server_handshake_traffic_secret:", server_handshake_traffic_secret.hex())


server_write_key = roll13.crypto.hkdf.hkdf_expand_label(roll13.crypto.sha.sha256, 32, server_handshake_traffic_secret, b"key", b"", 16)
server_write_iv = roll13.crypto.hkdf.hkdf_expand_label(roll13.crypto.sha.sha256, 32, server_handshake_traffic_secret, b"iv", b"", 12)
print("server write keu:", server_write_key.hex(), server_write_iv.hex())

client_write_key = roll13.crypto.hkdf.hkdf_expand_label(roll13.crypto.sha.sha256, 32, client_handshake_traffic_secret, b"key", b"", 16)
client_write_iv = roll13.crypto.hkdf.hkdf_expand_label(roll13.crypto.sha.sha256, 32, client_handshake_traffic_secret, b"iv", b"", 12)
print("client write keu:", client_write_key.hex(), client_write_iv.hex())

"""
derived_secret = derive_secret(dh_secret, b"derived", roll13.crypto.sha.sha256(b""))
print("derived_secret:", derived_secret.hex())

master_secret = extract_secret(derived_secret)
print("master_secret:", master_secret.hex())

client_application_traffic_secret = derive_secret(master_secret, b"c ap traffic", transcript_hash)
print("client_application_traffic_secret:", client_application_traffic_secret.hex())
server_application_traffic_secret = derive_secret(master_secret, b"s ap traffic", transcript_hash)
print("server_application_traffic_secret:", server_application_traffic_secret.hex())
"""

res = TLSPlaintext.read_from(sf)
print("RECEIVING:")
print(res)

res = TLSPlaintext.read_from(sf)
print("RECEIVING:")
#print(res)

reconstructed = io.BytesIO()
res.write_to(reconstructed)
reconstructed = bytes(reconstructed.getbuffer())

foo = res.fragment
msg, tag = foo[:-16], foo[-16:]
print(len(msg), msg.hex())
blah = reconstructed[:5]
pt = roll13.crypto.gcm.gcm_ad(server_write_iv, msg, blah, tag, roll13.crypto.aes.AES128(server_write_key).encrypt_block)

#print(pt.hex())

barbie = io.BytesIO(pt)
foo = Handshake.read_from(barbie)
print("barbie", barbie.read(1))
print(foo)


res = TLSPlaintext.read_from(sf)
print("RECEIVING:")
#print(res)

reconstructed = io.BytesIO()
res.write_to(reconstructed)
reconstructed = bytes(reconstructed.getbuffer())

foo = res.fragment
msg, tag = foo[:-16], foo[-16:]
blah = reconstructed[:5]
bar = bytearray(server_write_iv)
bar[-1] ^= 1
pt = roll13.crypto.gcm.gcm_ad(bar, msg, blah, tag, roll13.crypto.aes.AES128(server_write_key).encrypt_block)

#print(pt.hex())
foo = Handshake.read_from(io.BytesIO(pt))
print(foo)


res = TLSPlaintext.read_from(sf)
print("RECEIVING:")
print(res)

res = TLSPlaintext.read_from(sf)
print("RECEIVING:")
print(res)
