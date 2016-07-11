#!/usr/bin/env python
# -*- coding: utf-8 -*-
import jks, sys, base64, textwrap

def try_decrypt(o, storepass, keypass):
	if o.is_decrypted():
		return True
	try:
		o.decrypt(storepass)
	except jks.util.DecryptionFailureException:
		pass
	if o.is_decrypted():
		return True
	try:
		o.decrypt(keypass)
	except jks.util.DecryptionFailureException:
		pass
	return o.is_decrypted()

def print_pem(t, der_bytes):
	print('-----BEGIN {}-----'.format(t))
	print('\r\n'.join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)))
	print('-----END {}-----\n'.format(t))

def view_jks(jks_file, storepass, keypass, verbose=False):
	try:
		ks = jks.KeyStore.load(jks_file, storepass)
	except jks.util.KeystoreSignatureException:
		print('error: wrong storepass')
		sys.exit(1)
	
	for k, v in ks.private_keys.items():
		if try_decrypt(v, storepass, keypass):
			print('PrivateKey: {} (decrypted)'.format(k))
			if not verbose:
				continue
			if v.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
				print_pem('RSA PRIVATE KEY', v.pkey)
			else:
				print_pem('PRIVATE KEY', v.pkey_pkcs8)
		else:
			print('PrivateKey: {} (cannot decrypt)'.format(k))
		
		if not verbose:
			continue
		for c in v.cert_chain:
			print_pem('CERTIFICATE', c[1])
	
	for k, v in ks.certs.items():
		print('Certificate: {}'.format(k))
		if not verbose:
			continue
		print_pem('CERTIFICATE', v.cert)
		
	for k, v in ks.secret_keys.items():
		print('SecretKey: {}'.format(k))
		if not verbose:
			continue
		print('\tAlgorithm: {}'.format(v.algorithm))
		print('\tKey size: {} bits'.format(v.key_size))
		print('\tKey: {}\n'.format(''.join("{:02x}".format(b) for b in bytearray(sk.key))))

if __name__ == '__main__':
	reload(sys)
	sys.setdefaultencoding('utf8')
	verbose = sys.argv[1] == '-v' if len(sys.argv) > 1 else False
	addition = 1 if verbose else 0
	if len(sys.argv) < (3 + addition):
		print('usage: {} [-v] <jks_file> <storepass> [keypass]'.format(sys.argv[0]))
		sys.exit(1)
	jks_file = sys.argv[1 + addition].strip()
	storepass = sys.argv[2 + addition].strip()
	keypass = sys.argv[3 + addition].strip() if len(sys.argv) > (3 + addition) else ''
	view_jks(jks_file, storepass, keypass, verbose)
