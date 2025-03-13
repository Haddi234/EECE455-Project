class GF2_m:
    IRREDUCIBLE_POLYS = {
        2: 0b111,
        3: 0b1011,
        4: 0b10011,
        5: 0b100101,
        6: 0b1000001,
        7: 0b10000001,
        8: 0b100011011
    }

    def __init__(self, m: int):
        if m < 2 or m > 8:
            raise ValueError("Degree must be between 2 and 8")
        self.m = m
        self.poly = GF2_m.IRREDUCIBLE_POLYS[m]
        self.field_mask = (1 << m) - 1  # Mask to keep values within GF(2^m)

    def validate(self, a: int):
        if a < 0:
            raise ValueError(f"Negative values are not allowed in GF(2^{self.m})")

    def add(self, a: int, b: int) -> int:
        """ Addition (same as subtraction in GF(2^m)) """
        self.validate(a)
        self.validate(b)
        result = a ^ b  # XOR for addition
        return self.reduce_modulo(result)  # Apply modulo reduction

    def sub(self, a: int, b: int) -> int:
        """ Subtraction (same as addition in GF(2^m)) """
        return self.add(a, b)  # Apply modulo reduction via add()

    def mul(self, a: int, b: int) -> int:
        """ Multiplication with modulo reduction """
        self.validate(a)
        self.validate(b)
        res = 0
        while b:
            if b & 1:
                res ^= a  # Add (XOR) a if the lowest bit of b is 1

            # Shift a to the left and reduce mod poly if necessary
            a <<= 1
            if a & (1 << self.m):  # If degree exceeds field degree
                a ^= self.poly  # Reduce modulo irreducible polynomial

            b >>= 1  # Shift b to the right
        
        return self.reduce_modulo(res)  # Apply modulo reduction

    def div(self, a: int, b: int) -> int:
        """ Division using multiplicative inverse """
        if b == 0:
            raise ValueError("Division by zero is not allowed in GF(2^m)")
        result = self.mul(a, self.inverse(b))  # Multiply by inverse
        return self.reduce_modulo(result)  # Apply modulo reduction

    def inverse(self, a: int) -> int:
        """ Finds the multiplicative inverse using the Extended Euclidean algorithm """
        if a == 0:
            raise ValueError("Zero has no multiplicative inverse in GF(2^m)")

        # Ensure 'a' is reduced mod the irreducible polynomial
        a = self.reduce_modulo(a)

        u, v = a, self.poly  # u is the element, v is the irreducible polynomial
        g1, g2 = 1, 0  # g1 will store the inverse

        while u != 1:
            deg_u, deg_v = u.bit_length() - 1, v.bit_length() - 1

            # Ensure u is the larger degree polynomial
            if deg_u < deg_v:
                u, v = v, u
                g1, g2 = g2, g1  # Swap tracking variables
                deg_u, deg_v = deg_v, deg_u  # Recalculate degrees

            shift = deg_u - deg_v

            # Prevent negative shifts
            if shift < 0:
                raise ValueError(f"Inverse calculation failed in GF(2^{self.m}). Negative shift detected.")

            u ^= v << shift
            g1 ^= g2 << shift

            # Ensure u remains within GF(2^m) by reducing modulo the field
            u &= self.field_mask
            g1 &= self.field_mask

            # Prevent infinite loops
            if u == 0:
                raise ValueError(f"Inverse calculation failed in GF(2^{self.m}). Element is not invertible.")

        return g1 & self.field_mask  # Ensure result is within GF(2^m)

    def reduce_modulo(self, poly: int) -> int:
        """ Reduce a polynomial mod the irreducible polynomial """
        while poly.bit_length() > self.m:
            shift = poly.bit_length() - self.m - 1
            poly ^= self.poly << shift
        return poly & self.field_mask  # Ensure it fits within GF(2^m)
