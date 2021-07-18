from .utils import *

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
		
		#fragment_buf = io.BytesIO(sf.read(length))
		
		if type_ == ContentType.alert:
			fragment = Alert.read_from(sf)
		elif type_ == ContentType.handshake:
			fragment = Handshake.read_from(sf)
		else:
			# TODO: error
			fragment = sf.read(length)
		
		# TODO: check if we actually read the correct length
		
		return cls(
			type_=type_,
			legacy_record_version=legacy_record_version,
			fragment=fragment
		)
	
	def write_to(self, sf):
		sf.write(int(self.type).to_bytes(1, "big"))
		sf.write(self.legacy_record_version.to_bytes(2, "big"))
		sf.write(len(self.fragment).to_bytes(2, "big"))
		sf.write(self.fragment)
		sf.flush()

"""
We need to establish queues from which Handshake and Application Data
fragments can be read.

Alerts will throw an exception

https://www.codementor.io/@arpitbhayani/building-finite-state-machines-with-python-coroutines-15nk03eh9l

https://mleue.com/posts/yield-to-async-await/

"""


class RecordReaderState(Enum):
	READING_HANDSHAKE = 1


class RecordReader():
	state = RecordReaderState.READING_HANDSHAKE
	pass
