#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys
import hmac, hashlib, base64
from binascii import hexlify
from struct import Struct
from operator import xor
from itertools import starmap

from Crypto.Cipher import AES

# NOTE: pbkdf2_ taken from https://github.com/mitsuhiko/python-pbkdf2
#       + fixes and py2/py3 compatibility
_PY3 = sys.version_info[0] > 2
_text_type = str if _PY3 else unicode
if not _PY3:
	from itertools import izip as zip
_pack_int = Struct('>I').pack
def _bytes(s, enc='utf-8', err='strict'):
	return s.encode(enc, err) if isinstance(s, _text_type) else s
def _string(s, enc='utf-8', err='strict'):
	return s.decode(enc, err) if not isinstance(s, _text_type) else s
def _hex(s):
	return str(hexlify(s), encoding='utf-8') if _PY3 else s.encode('hex')
def _range(*args):
	return range(*args) if _PY3 else xrange(*args)

def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
	return _hex(pbkdf2_bin(data, salt, iterations, keylen, hashfunc))
	
def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
	hashfunc = hashfunc or hashlib.sha1
	mac = hmac.new(_bytes(data), None, hashfunc)
	def _pseudorandom(x, mac=mac):
		h = mac.copy()
		h.update(_bytes(x))
		return [y for y in h.digest()] if _PY3 else map(ord, h.digest())
	buf = []
	for block in _range(1, -(-keylen // mac.digest_size) + 1):
		rv = u = _pseudorandom(_bytes(salt) + _pack_int(block))
		for i in _range(iterations - 1):
			u = _pseudorandom(bytes(u) if _PY3 else ''.join(map(chr, u)))
			rv = list(starmap(xor, zip(rv, u)))
		buf.extend(rv)
	return bytes(buf)[:keylen] if _PY3 else ''.join(map(chr, buf))[:keylen]


def java_pad(s, block_size=16, padding='\n'):
	return s + (block_size - len(s) % block_size) * padding

# convert [-13, 3, -66, ..] to [243, 3, 190] ...
def java_iv(iv):
	iv = [i % 256 for i in iv]
	return bytes(iv) if _PY3 else ''.join(map(chr, iv))

# DigestAlgorithm("SHA1")
def java_hash_key(key, hashfunc=hashlib.sha1):
	b64 = base64.b64encode(hashfunc(_bytes(key)).digest())
	return _bytes(_string(b64).rstrip('=') + chr(10))

# SecretKeyType("PBKDF2WithHmacSHA1")
def java_secret_key(key, salt, iterations, keylen, hashfunc=hashlib.sha1):
	return pbkdf2_bin(key, salt, iterations, keylen, hashfunc)

# Algorithm("AES/CBC/PKCS5Padding")
def java_decrypt(secret_key, iv, ciphertext):
	cipher = AES.new(secret_key, AES.MODE_CBC, iv)
	return _string(cipher.decrypt(ciphertext)).rstrip('\n')

# Algorithm("AES/CBC/PKCS5Padding")
def java_encrypt(secret_key, iv, plaintext):
	cipher = AES.new(secret_key, AES.MODE_CBC, iv)
	return cipher.encrypt(java_pad(plaintext))

def main():
	password = 'ExamplePassword'
	salt = password + password
	hash_key = java_hash_key(password, hashlib.sha1)
	secret_key = java_secret_key(hash_key, salt, 65536, 16, hashlib.sha1)
	iv = java_iv([-45, 136, -15, -30, 233, 197, -58, -40, -172, -17, -108, 146, 17, 20, -105, 117])
	#iv = os.urandom(16)
	ct = java_encrypt(secret_key, iv, 'example ciphertext')
	print('encrypted: {}'.format(_hex(ct)))
	print('encrypted: {}'.format(base64.b64encode(ct)))
	pt = java_decrypt(secret_key, iv, ct)
	print('decrypted: {}'.format(pt))

if __name__ == '__main__':
	main()
