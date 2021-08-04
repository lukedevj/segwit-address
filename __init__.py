from ecdsa.ecdsa import Public_key as ECDSAPublicKey
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.ellipticcurve import Point
from ecdsa.keys import VerifyingKey
from ecdsa.curves import SECP256k1
from base58 import b58decode_check, b58encode_check
from bech32 import encode as bech32_encode
from binascii import unhexlify, hexlify
import hashlib, hmac

class PublicKey:

    def __init__(self, chain : None=None, verify : None=None):
        self.chain = chain
        self.point = (
            verify.pubkey.point if not verify == None else None
        )
        self.to_hex = lambda x, y: (
            ('{0:0%sx}' % y).format(x).lower().encode()
        )
        self.get_hex = lambda : (
            self.to_hex(2 + (self.point.y() & 1), 2) + self.to_hex(self.point.x(), 64)
        )
        self.create = lambda x, y: (
            VerifyingKey.from_public_point(Point(SECP256k1.curve, x, y), curve=SECP256k1)
        )

    def derive(self, path : str='0/0') -> bytes:
        node = self
        for p in path.split('/'):
            assert p.find('m') == -1 and p.find('\'') == -1, 'Can\'t be used to generate private keys'
            index = int(p)
            assert index >= 0, 'Index can\'t be less than 0'
            node = node.get_child(index)
            
        data = unhexlify(node.get_hex())
        return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

    def get_child(self, data) -> object:
        data = self.get_hex() + self.to_hex(data, 8)
        data = hmac.new(unhexlify(self.chain), unhexlify(data), hashlib.sha512).digest()
        left, right = (
            hexlify(data[:32]), hexlify(data[32:])
        )
        generate = SECP256k1.generator
        point = (
            ECDSAPublicKey(generate, generate * int(left, 16)).point
        ) + self.point

        return __class__(
            right, self.create(point.x(), point.y())
        )

    def verifyng(self, data) -> object:
        byte = data[0]
        if not isinstance(byte, int): byte = ord(byte)
        if byte == 4:
            assert len(data) == 65, 'Invalid key length(65).'
            return self.create(
                int(hexlify(data[1:33]), 16), int(hexlify(data[33:]), 16)
            )

        assert byte in [2, 3] , 'The given key is not in a known format.'
        assert len(data) == 33, 'Invalid key length.'

        curve = SECP256k1.curve

        p, a, b = curve.p(), curve.a(), curve.b()
        x = int(hexlify(data[1:]), 16)
        alpha = (pow(x, 3, p) + a * x + b) % p
        beta = square_root_mod_prime(alpha, p)

        if not bool(byte & 0x01) == bool(beta & 1):
            return self.create(x, p - beta)

        return self.create(x, beta)

class Address:

    def __init__(self, pub, path=[0, -9]):
        self.pub = b58decode_check(
            (str(pub).encode() if not type(pub) == bytes else pub)
        )
        self.path = (
            list(path) if type(path) in [set, tuple] else path
        )
        self.path = (
            str(self.path).split('/') if not type(self.path) == list else self.path
        )

        if int(self.path[1]) < 0: self.path[1] = 0

        self.path = '/'.join([str(path) for path in self.path])
        self.addr = self.deserialize()

        self.segwit = lambda : bech32_encode('bc', 0, self.addr)
        self.legacy = lambda : b58encode_check(b'\x00' + self.addr).decode()

    def deserialize(self) -> object:
        chain, verify = self.pub[13:45].hex(), self.pub[45:]
        assert verify[0] in [2, 3, 4], 'Invalid pub prefix.'
        verify = PublicKey().verifyng(verify)
        return PublicKey(chain, verify).derive(self.path)
