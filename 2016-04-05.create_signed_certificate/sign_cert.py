#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# 1. generate CA key:
# `openssl genrsa -out ca.key 2048` or `openssl genrsa -des3 -out ca.key 2048`
#
# 2. generate CA crt:
# `openssl req -new -x509 -days 365 -key ca.key -out ca.crt`
#
from __future__ import print_function
import os, sys, hashlib
from OpenSSL import crypto

def load_ca_certs(**kwargs):
	_cdir, _ca = os.path.realpath(sys.path[0]), {}
	for k, v in {'ca_key_path': 'ca.key', 'ca_crt_path': 'ca.crt'}.items():
		_ca[k] = (kwargs.get(k, '')) or v
	for k in ['ca_key', 'ca_crt']:
		_ca[k] = kwargs.get(k)
		if _ca[k] is not None:
			continue
		p = _ca[k + '_path']
		if not os.path.isabs(p):
			p = os.path.join(_cdir, p)
		if not os.path.isfile(p):
			raise ValueError('Invalid {}: "{}"'.format(k + '_path', v))
		_ca[k] = open(p).read()
	ca_pwd = kwargs.get('ca_passphrase')
	ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, _ca['ca_crt'])
	ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, _ca['ca_key'], ca_pwd)
	return (ca_key, ca_crt)

def create_signed_cert(**kwargs):
	country_name = kwargs.get('C', 'CA').strip()[:2]
	state = kwargs.get('ST', '').strip()
	locality = kwargs.get('L', '').strip()
	org_name = kwargs.get('O', 'Shake it Vera').strip()
	org_unit = kwargs.get('OU', '').strip()
	common_name = kwargs.get('CN', 'Wastelandus').strip()
	
	email_address = kwargs.get('emailAddress', '').strip()
	days = int(kwargs.get('days', 365))
	sign_algorithm = kwargs.get('sign_algorithm', 'sha256')
	
	if len(country_name) < 2:
		raise ValueError('Invalid certificate field: Country Name (C)')
	if not org_name:
		raise ValueError('Invalid certificate field: Organization Name (O)')
	if not common_name:
		raise ValueError('Invalid certificate field: Common Name (CN)')
	
	ca_key, ca_crt = load_ca_certs(**kwargs)
	serial = int(hashlib.sha256(common_name).hexdigest(), 16) % sys.maxsize
	
	cert_key = crypto.PKey()
	cert_key.generate_key(crypto.TYPE_RSA, 2048)
	
	cert_crt = crypto.X509()
	s = cert_crt.get_subject()
	s.C = country_name
	if state:
		s.ST = state
	if locality:
		s.L = locality
	s.O = org_name
	if org_unit:
		s.OU = org_unit
	s.CN = common_name
	if email_address:
		s.emailAddress = email_address
	cert_crt.gmtime_adj_notBefore(0)
	cert_crt.gmtime_adj_notAfter(60*60*24 * days)
	cert_crt.set_issuer(ca_crt.get_subject())
	cert_crt.set_serial_number(serial)
	cert_crt.set_pubkey(cert_key)
	cert_crt.sign(ca_key, sign_algorithm)
	
	cert_crt = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_crt)
	cert_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key)
	return (cert_key, cert_crt)

def main():
	key, crt = create_signed_cert(
		ca_key_path = 'ca.key',
		ca_crt_path = 'ca.crt',
		days = 365*10)
	open('test.key', 'w').write(key)
	open('test.crt', 'w').write(crt)

if __name__ == '__main__':
	reload(sys)
	sys.setdefaultencoding('utf8')
	main()
