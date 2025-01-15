#
#	Filename pc1char.py
#
#	Purpose:  This program transplant PC1 cipher in C/C++ version into Python
#			  The bugs hidden in deep were fixed, so this python version 
#			  is compatible with versions in C/C++ and java
#			  for more information please contact Alexander Pukall
#
#	Author:  Huey Jiang		huey_jiang@yahoo.com
#
#	Date:	March 13, 2009
#
class PC1:
	def __init__(self):
		self.cle = []
		self.x1a0 = []
		
		for name in ("ax", "bx", "cx", "dx", "si", "tmp", "x1a2", "res", "pki", "inter", "cfc", "cfd", "compte", "pkc"):
			setattr(self, name, 0)
		
	def fin(self):
		del self.cle[0:]
		del self.x1a0[0:]
		
		for i in range(9):
			self.x1a0.insert(i, 0)
		for i in range(16):
			self.cle.insert(i, 0)
			
		for name in ("ax", "bx", "cx", "dx", "si", "tmp", "x1a2", "res", "pki", "inter", "cfc", "cfd", "compte", "pkc"):
			setattr(self, name, 0)
	def code(self):
		self.dx = self.x1a2 + self.pki
		self.ax = self.x1a0[self.pki]
		self.cx = 0x015a
		self.bx = 0x4e35
	
		self.tmp = self.ax
		self.ax = self.si
		self.si = self.tmp
		
		self.tmp = self.ax
		self.ax = self.dx
		self.dx = self.tmp
		
		if self.dx != 0:
			self.ax = (self.ax * self.bx) & 0xffff
			
		self.tmp = self.ax
		self.ax = self.cx
		self.cx = self.tmp
		
		if self.ax != 0:
			self.ax = (self.ax * self.si) & 0xffff
			self.cx = self.ax + self.cx
		
		self.tmp = self.ax
		self.ax = self.si
		self.si = self.tmp
		self.ax = (self.ax * self.bx) & 0xffff
		self.dx = self.cx + self.dx
	
		self.ax = self.ax + 1
		
		self.x1a2 = self.dx
		self.x1a0[self.pki] = self.ax
		
		self.res = (self.ax ^ self.dx) & 0xffff
		self.pki = self.pki + 1
		
	def assemble(self):
		self.x1a0[0] = (self.cle[0] * 256) + self.cle[1]
		
		self.code()
		self.inter = self.res
		
		self.x1a0[1] = self.x1a0[0] ^ ((self.cle[2] * 256) + self.cle[3])
		self.code()
		self.inter = self.inter ^ self.res
		
		self.x1a0[2] = self.x1a0[1] ^ ((self.cle[4] * 256) + self.cle[5])
		self.code()
		self.inter = self.inter ^ self.res
		
		self.x1a0[3] = self.x1a0[2] ^ ((self.cle[6] * 256) + self.cle[7])
		self.code()
		self.inter = self.inter ^ self.res
		
		self.x1a0[4] = self.x1a0[3] ^ ((self.cle[8] * 256) + self.cle[9])
		self.code()
		self.inter = self.inter ^ self.res
		
		self.x1a0[5] = self.x1a0[4] ^ ((self.cle[10] * 256) + self.cle[11])
		self.code()
		self.inter = self.inter ^ self.res
		self.x1a0[6] = self.x1a0[5] ^ ((self.cle[12] * 256) + self.cle[13])
		self.code()
		self.inter = self.inter ^ self.res
		
		self.x1a0[7] = self.x1a0[6] ^ ((self.cle[14] * 256) + self.cle[15])
		self.code()
		self.inter = self.inter ^ self.res
		
		self.pki = 0
	def encrypt(self, plaintext, passwd):
		encrypted = ''
		dummy = []
		
		self.fin()
		for p in passwd:
			dummy.append( ord(p))
	
		# Take care of key first
		paslen = len(passwd)
		keylen = len(self.cle)
		if paslen >= keylen:
			newkey = dummy[:keylen]
		else:
			lefto = self.cle[paslen:]
			newkey = dummy + lefto
	
		self.cle = newkey
		
		# OK, rock starts	
		for c in plaintext:
			self.pkc = ord(c)
			
			self.assemble()
			
			self.cfc = self.inter >> 8
			
			self.cfd = self.inter & 255
			
			for i in range(16):
				self.cle[i] = self.cle[i] ^ self.pkc
			
			self.pkc = self.pkc ^ (self.cfc ^ self.cfd)
			
			d = self.pkc >> 4
			e = self.pkc & 15
			
			dd = 0x61+d;
			ee = 0x61+e;
			
			encrypted = encrypted + chr(dd) + chr(ee)
		return encrypted
	def decrypt(self, ciphertext, passwd):
		decrypted = ''
		dummy = []
		dds = ''
		ees = ''
		
		self.fin()
		for p in passwd:
			dummy.append( ord(p))
	
		# Take care of key first
		paslen = len(passwd)
		keylen = len(self.cle)
		if paslen >= keylen:
			newkey = dummy[:keylen]
		else:
			lefto = self.cle[paslen:]
			newkey = dummy + lefto
	
		self.cle = newkey
		
		cilen = len(ciphertext)
	
		for i in range(0, cilen, 2):
			dds = dds + ciphertext[i]

		for i in range(1, cilen+1, 2):
			ees = ees + ciphertext[i]

		halen = cilen / 2
	
		for i in range(halen):
			dd = ord(dds[i])
		
			d = dd - 0x61
			
			d = d << 4
		
			ee = ord(ees[i])
			e = ee - 0x61
		
			self.pkc = d + e

			self.assemble()
	
			self.cfc = self.inter >> 8
			self.cfd = self.inter & 255
		
			dec = self.pkc ^ (self.cfc ^ self.cfd)
			
			decrypted = decrypted + chr(dec)	
			for j in range(16):
				self.cle[j] = self.cle[j] ^ dec
			
			
		return decrypted
if __name__ == "__main__":
	p = PC1()
	# you should change key "Remsaalps!123456" 
	ec = p.encrypt("123abc", "Remsaalps!123456")
	print ec
	dc = p.decrypt(ec, "Remsaalps!123456")
	print dc