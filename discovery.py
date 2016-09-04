#!/usr/bin/python

import re,os
users={}
hostnames=[]

# extracting usernames and home folders
filename = '/etc/passwd'
try:
	hosts=open(filename,'r')
	next(hosts)
	for line in hosts:
		line = line.split(':')
		users[line[0]] = line[5]
	hosts.close()
except:
	pass

filename = '/etc/hosts'
try:
	hosts = open(filename,'r')
	for line in hosts:
		line = line.strip()
		word = line.split()
		if word:
			#checking if hostname is not an IP address
			m1 = re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',word[0])
			m2 = re.search(".*::.*",word[0])
			if m1 or m2:
				for i in range(len(word)-1):
					hostnames.append(word[i+1])
	hosts.close()
except:
	pass

filename = '/etc/ssh/ssh_config'
try:
	hosts = open(filename,'r')
	for line in hosts:
		line = line.strip()
		word = line.split()
		if('Host' in word):
			nextword = word.index("Host")
			m1 = re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',word[nextword+1])
			b = re.match("[*?a-zA-Z0-9][a-zA-Z0-9_-]*",word[nextword+1])
			if not m1 and b:
				for nextword in range(len(word)-1):
					hostnames.append(word[nextword+1])
		elif('HostName' in word):
			nextword = word.index("HostName")
			m1 = re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',word[nextword+1])
			b = re.match("[*?a-zA-Z0-9][a-zA-Z0-9_-]*",word[nextword+1])
			if not m1 and b:
				for nextword in range(len(word)-1):
					hostnames.append(word[nextword+1])
	hosts.close()	
except:
	pass
	
filename = '/etc/ssh/ssh_known_hosts'	
try:
	hosts = open(filename,'r')
	for line in hosts:
		word = line.split()
		if(word[0].startswith('#') or word[0].startswith('|') or word[0].startswith('@revoked')):
			continue
		else:
			for w in word:
				# ignore comments
				if w.startswith('#'):
					break
				x = w.split(',')
				for y in x:
					if ('[' in y and ']' in y and ':' in y):
						i1 = y.index('[')
						i2 = y.index(']')				
						host = y[i1+1:i2-1]
					else:
						host = y	
					n = re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",host)
		       			if not n:
						m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",host)	
						m2 = re.match("[A-Za-z0-9*][a-zA-Z0-9_-]*(\.)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",host)
						if m1:
							#extracting everything after '@'
							i = host.index('@')
							hostnames.append(host[i+1:])
						if m2:
							hostnames.append(host)
				m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",w)	
				m2 = re.match("(^=)(.*)\.(.*)\.(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",w)
				m3 = re.match("[a-zA-Z]+",w)
				if w == "@cert-authority":
					continue				
				if m1:
					i = w.index('@')
					hostnames.append(w[i+1:])
				elif m2 or m3:
					hostnames.append(w)	
	hosts.close()
except:
	pass

for key in users:
	filename = users[key]+"/.ssh/config"	
	try:
		hosts = open(filename,'r')
		for line in hosts:
			line = line.strip()
			word = line.split()
			c = 0	
			for w in word:
				if '#' in w:
					c = 1
			if(c==1):
				continue
			if('Host' in word):
				nextword = word.index("Host")
				a = re.match("[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*",word[nextword+1])
				if not a:
					for nextword in range(len(word)-1):
						m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",word[nextword+1])
						m2 = re.match("[a-zA-Z*][a-zA-Z]+(@)[a-zA-Z]+",word[nextword+1])	
						if m1 or m2:
							i = word[nextword+1].index('@')
							f = word[nextword+1]
							hostnames.append(f[i+1:])
						else:
							hostnames.append(word[nextword+1])
			elif('HostName' in word):
				nextword = word.index("HostName")
				a = re.match("[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*",word[nextword+1])
				if not a:
					for nextword in range(len(word)-1):
						m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",word[nextword+1])
						m2 = re.match("[a-zA-Z*][a-zA-Z]+(@)[a-zA-Z]+",word[nextword+1])		
						if m1 or m2:
							i = word[nextword+1].index('@')
							f = word[nextword+1]
							hostnames.append(f[i+1:])
						else:
							hostnames.append(word[nextword+1])
		hosts.close()
	except:
		pass

for key in users:
	filename = users[key]+"/.ssh/known_hosts"
	try:
		hosts = open(filename,'r')
		for line in hosts:
			word = line.split()
			if(word[0].startswith('#') or word[0].startswith('|') or word[0].startswith('@revoked')):
				continue
			else:
				w = word[0]
				x = w.split(',')
				for y in x:
					if y.startswith('#'):
						break
					if ('[' in y and ']' in y and ':' in y):
						i1 = y.index('[')
						i2 = y.index(']')				
						host = y[i1+1:i2-1]
					elif w == "@cert-authority":
						continue	
					else:
						host = y	
					n = re.match("[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*",host)
		       			if not n:
						m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",host)	
						if m1:
							i = host.index('@')
							hostnames.append(host[i+1:])
						else:
							hostnames.append(host)
		hosts.close()
	except:
		pass
#extracting using "from=" , permitopen=" and checking last word of every line for valid host name
for key in users:
	filename = users[key]+"/.ssh/authorized_keys"
	try:
		hosts = open(filename,'r')
		for line in hosts:
			word = line.split()
			if(word and (word[0].startswith('#') or word[0].startswith('|') or word[0].startswith('@revoked'))):
				continue
			elif word:
				for w in word:	
					if w.startswith('#'):
						break
					m1 = re.match('(.*)==',w)
					m2 = re.match('(.*)==(.+)',w)
					if m1:
						i = word.index(w)
						if i<len(word)-1:
							nextword = word[i+1]
						elif m2:
							nextword = w.find(w,w.index('=')+2,len(w))
						if m1 or m2:
							a = re.match("[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*",nextword)
							if not a:
								m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",nextword)	
								if m1:
									i = nextword.index('@')
									hostnames.append(nextword[i+1:])
								else:
									hostnames.append(nextword)
											
					match = re.search('from="(.+)"',w)
					if match:
						match = match.group(1)	
						x = match.split(',')
						for y in x:	
							n = re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",y)
		       					if not n:
								m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",y)	
								if m1:
									i = y.index('@')
									hostnames.append(y[i+1:])
								else:
									hostnames.append(y)
					match = re.search('(.+)from="(.+)"',w)
					if match:
						x = w.split(',')
						for y in x:
							m = re.search('from="(.+)"',y)
							if m:
								m = m.group(1)
								n = re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",m)
		       						if not n:
									m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",m)	
									if m1:
										i = m.index('@')
										hostnames.append(m[i+1:])
									else:
										hostnames.append(m)
												
					if w.startswith('permitopen="'):
						y=w.split(',')
						for x in y:
							m = re.search('permitopen="(.+):[0-9]+"',x)
							if m:
								m = m.group(1)	
								n = re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",m)
		       						if not n:
									m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",m)	
									if m1:
										i = m.index('@')
										hostnames.append(m[i+1:])
									else:
										hostnames.append(m)
								
					ma = re.search('(.+)permitopen="(.+):[0-9]+"',w)
					if ma:
						y=w.split(',')
						for x in y:
							p = re.search('permitopen="(.+):[0-9]+"',x)
							if p:
								p = p.group(1)	
								n = re.match("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",p)
		       						if not n:
									m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",p)	
									if m1:
										i = p.index('@')
										hostnames.append(p[i+1:])
									else:
										hostnames.append(p)
					m1 = re.match("[a-zA-Z0-9_*][a-zA-Z0-9]+(@)[a-zA-Z0-9_-]+(\.)(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",w)	
					m2 = re.match("(^=)(.*)\.(.*)\.(com|net|mil|edu|org|COM|ORG|MIL|EDU|NET)",w)
					#m3 = re.match("[a-zA-Z]+",w)
					if m1:
						i = w.index('@')
						hostnames.append(w[i+1:])
					elif m2:
						hostnames.append(w)	
		hosts.close()
	except:
		pass

original = []

for i in hostnames:
	if i not in original:
		original.append(i)

for i in original:
	print i

