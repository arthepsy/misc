#!/usr/bin/env python
from pysqlcipher import dbapi2 as sqlite
import getopt, sys

def usage(err=None):
	p = sys.argv[0]
	print('usage: {0} <command> -k <key> [options] <src.db> <dst.db>'.format(p))
	if err is not None:
		print('\n{0}'.format(err))
	print('\ncommand:')
	print('   encrypt       encrypt database')
	print('   decrypt       decrypt database')
	print('\noptions:')
	print('   -c CIPHER     encryption algorithm')
	print('   -i ITER       number of iterations')
	print('   -p SIZE       database page size (default: 1024)')
	print('\nversion settings:')
	print('   -V 2          cipher: aes-256-cbc, iterations: 4000')
	print('   -V 3          cipher: aes-256-cfb, iterations: 64000')
	sys.exit(1)


def _encrypt(src, dst, key, cipher, kdf_iter, cipher_page_size):
	conn = sqlite.connect(src)
	c = conn.cursor()
	c.execute("ATTACH DATABASE '{0}' AS encrypted KEY '{1}'".format(dst, key))
	if kdf_iter is not None:
		c.execute("PRAGMA encrypted.kdf_iter={0}".format(kdf_iter))
	if cipher is not None:
		c.execute("PRAGMA encrypted.cipher='{0}'".format(cipher))
	if cipher_page_size is not None:
		c.execute("PRAGMA encrypted.cipher_page_size={0}".format(cipher_page_size))
	c.execute("SELECT sqlcipher_export('encrypted');")
	c.execute("DETACH DATABASE encrypted")
	c.close()

def _decrpyt(src, dst, key, cipher, kdf_iter, cipher_page_size):
	conn = sqlite.connect(src)
	c = conn.cursor()
	c.execute("PRAGMA key='{0}'".format(key))
	if kdf_iter is not None:
		c.execute("PRAGMA kdf_iter={0}".format(kdf_iter))
	if cipher is not None:
		c.execute("PRAGMA cipher='{0}'".format(cipher))
	if cipher_page_size is not None:
		c.execute("PRAGMA cipher_page_size={0}".format(cipher_page_size))
	c.close()
	
	c = conn.cursor()
	try:
		c.execute('SELECT COUNT(*) from sqlite_master')
		count = c.fetchone()[0]
	except sqlite.DatabaseError as ex:
		print('wrong key: {0}'.format(ex))
		sys.exit(1)
	finally:
		c.close()
	
	c = conn.cursor()
	c.execute("ATTACH DATABASE '{0}' AS plaintext KEY ''".format(dst))
	c.execute("SELECT sqlcipher_export('plaintext');")
	c.execute("DETACH DATABASE plaintext")
	c.close()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		usage()
	command = sys.argv[1]
	if command not in ('encrypt', 'decrypt'):
		usage('invalid command: {0}'.format(command))
	try:
		opts, args = getopt.getopt(sys.argv[2:], 'k:c:i:p:V:', [])
	except getopt.GetoptError as err:
		usage(err)
	key = None
	cipher = None
	kdf_iter = None
	cipher_page_size = None
	for o, a in opts:
		if o == '-k':
			key = a
		elif o == '-c':
			cipher = a
		elif o == '-i':
			try:
				kdf_iter = int(a)
			except ValueError:
				usage('invalid iterations: {0}'.format(a))
		elif o == '-p':
			try:
				cipher_page_size = int(a)
			except ValueError:
				usage('invalid page size: {0}'.format(a))
		elif o == '-V':
			if a == '2':
				cipher = 'aes-256-cbc'
				kdf_iter = 4000
			elif a == '3':
				cipher = 'aes-256-cfb'
				kdf_iter = 64000
			else:
				usage('invalid SQLCipher version specified: {0}'.format(a))
	if len(args) != 2:
		usage()
	if key is None:
		usage('no key specified')
	src, dst = args[0], args[1]

	if command == 'encrypt':
		_encrypt(src, dst, key, cipher, kdf_iter, cipher_page_size)
	elif command == 'decrypt':
		_decrpyt(src, dst, key, cipher, kdf_iter, cipher_page_size)
	sys.exit(0)
