#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, re, glob
from io import StringIO, BytesIO
from lxml import etree

def get_text(xnode):
	if xnode is None:
		return ''
	if xnode.text is None:
		return ''
	return xnode.text.strip()

def analyze(config_file, users_dir, job_name, permission):
	parser = etree.XMLParser(recover=True)
	
	user_configs = glob.glob(users_dir + '/*/config.xml')
	users = set()
	roles = {}
	for user_config in user_configs:
		user_name = user_config.split('/')[-2:-1][0]
		users.add(user_name)
		doc = etree.parse(user_config, parser)
		for xnode in doc.xpath('//roles/string'):
			role = get_text(xnode)
			if not role: continue
			if not role in roles:
				roles[role] = set()
			roles[role].add(user_name)
	
	doc = etree.parse(config_file, parser)
	matched_users = {}
	for xrole in doc.xpath('//role'):
		role_name = xrole.get('name')
		role_pattern = xrole.get('pattern')
		# NOTE: job match
		if re.match(role_pattern, job_name) is None:
			continue
		permissions = set()
		for xperm in xrole.xpath('.//permission'):
			perm = get_text(xperm)
			if not perm: continue
			permissions.add(perm)
		# NOTE: permission check
		if not permission in permissions:
			continue
		for xsid in xrole.xpath('.//sid'):
			sid = get_text(xsid)
			if not sid: continue
			if sid not in users:
				for usid in roles[sid]:
					if usid not in matched_users:
						matched_users[usid] = set()
					matched_users[usid].add('BY_ROLE_AND_SID=' + role_name + '|' + sid)
			else:
				if sid not in matched_users:
					matched_users[sid] = set()
				matched_users[sid].add('BY_ROLE=' + role_name)
	
	if len(matched_users) == 0:
		return
	
	ml = max([len(x) for x in matched_users.keys()])
	print '# user'.ljust(ml - 1), ' role_name([role])'
	for user, why in sorted(matched_users.items()):
		roles = set()
		for w in why:
			wn, rn = w.split('=')
			if wn == 'BY_ROLE':
				roles.add(rn)
			else:
				rn, sid = rn.split('|')
				roles.add('{}({})'.format(rn, sid))
		print user.ljust(ml), ', '.join(roles)

if __name__ == '__main__':
	reload(sys)
	sys.setdefaultencoding('utf8')
	if len(sys.argv) < 4:
		print('usage: {} <config> <usersdir> <jobname> <permission>'.format(sys.argv[0]))
		sys.exit(1)
	config_file = sys.argv[1].strip()
	users_dir = sys.argv[2].strip().rstrip('/')
	job_name = sys.argv[3].strip()
	permission = sys.argv[4].strip()
	
	analyze(config_file, users_dir, job_name, permission)

