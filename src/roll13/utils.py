from enum import Enum, IntEnum

class PrettyPrintable:
	def __repr__(this):
		out = "<" + this.__class__.__name__ + "(\n"
		lines = []
		for k, v in this.__dict__.items():
			if type(v) is int:
				value = hex(v)
			elif type(v) is bytes:
				value = v.hex()
			else:
				value = repr(v).replace("\n", "\n  ")
			lines.append(f"  {k} = {value}")
		out += ",\n".join(lines)
		out += "\n)>"
		return out
