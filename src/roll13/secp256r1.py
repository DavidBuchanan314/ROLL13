# https://www.secg.org/SEC2-Ver-1.0.pdf

# secp256r1 is a Weierstrass curve, of the form
# y^2 = x^3 + ax + b (mod p)

# Section 2.7.2 - Curve Parameters

# the modulus of the prime field
p = 0xffffffff_00000001_00000000_00000000_00000000_ffffffff_ffffffff_ffffffff

# curve parameters
a = p - 3
b = 0x5ac635d8_aa3a93e7_b3ebbd55_769886bc_651d06b0_cc53b0f6_3bce3c3e_27d2604b

# the base point
Gx = 0x6b17d1f2_e12c4247_f8bce6e5_63a440f2_77037d81_2deb33a0_f4a13945_d898c296
Gy = 0x4fe342e2_fe1a7f9b_8ee7eb4a_7c0f9e16_2bce3357_6b315ece_cbb64068_37bf51f5

# the order of the field
n = 0xffffffff_00000000_ffffffff_ffffffff_bce6faad_a7179e84_f3b9cac2_fc632551
h = 1 # cofactor


class Point():
	def __init__(self, x, y, is_infinity=False):
		self.x = x
		self.y = y
		self.is_infinity = is_infinity
	
	def __repr__(self):
		if self.is_infinity:
			return "<Point(curve=secp256r1, Infinity)>"
		else:
			return f"<Point(curve=secp256r1, x={self.x:x}, y={self.y:x})>"
	
	def __copy__(self):
		return Point(self.x, self.y, self.is_infinity)
	
	def __eq__(self, other):
		if other.is_infinity:
			return self.is_infinity
		if self.is_infinity:
			return False
		return self.x == other.x and self.y == other.y
	
	# point negation
	def __neg__(self):
		if self.is_infinity:
			return self.__copy__()
		result = self.__copy__()
		result.y = (-self.y) % p
		return result
	
	# point addition
	# https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
	# TODO: implement __iadd__ (in-place add)
	def __add__(self, other):
		P = self
		Q = other
		if P == Infinity:
			return Q
		if Q == Infinity:
			return P
		if P.x == Q.x and P.y == -Q.y:
			return Infinity.__copy__()
		if P == Q: # point doubling
			tmp = ((3 * pow(P.x, 2, p) + a) * pow(2 * P.y, p - 2, p)) % p
		else:
			tmp = ((Q.y - P.y) * pow(Q.x - P.x, p - 2, p)) % p
		x3 = (pow(tmp, 2, p) - P.x - Q.x) % p
		y3 = (tmp*(P.x - x3) - P.y) % p
		return Point(x3, y3)
	
	# scalar multiplication via double-and-add
	def __mul__(self, n):
		assert(type(n) is int)
		Q = self
		R = Infinity.__copy__()
		while n:
			if n % 2:
				R += Q
			Q += Q
			n >>= 1
		return R

Infinity = Point(None, None, True)
G = Point(Gx, Gy)
