# -*- coding: utf-8 -*-

##############################################################################
#                        2014 E2OpenPlugins                                  #
#                                                                            #
#  This file is open source software; you can redistribute it and/or modify  #
#     it under the terms of the GNU General Public License version 2 as      #
#               published by the Free Software Foundation.                   #
#                                                                            #
##############################################################################
# Simulate the oe-a boxbranding module (Only functions required by OWIF)     #
##############################################################################

from Plugins.Extensions.OpenWebif.__init__ import _
from Components.About import about
from socket import has_ipv6
from Tools.Directories import fileExists, pathExists
import string
import os, hashlib

try:
	from Components.About import about
except:
	pass

tpmloaded = 1
try:
	from enigma import eTPM
	if not hasattr(eTPM, 'getData'):
		tpmloaded = 0
except:
	tpmloaded = 0

def validate_certificate(cert, key):
	buf = decrypt_block(cert[8:], key)
	if buf is None:
		return None
	return buf[36:107] + cert[139:196]

def get_random():
	try:
		xor = lambda a,b: ''.join(chr(ord(c)^ord(d)) for c,d in zip(a,b*100))
		random = urandom(8)
		x = str(time())[-8:]
		result = xor(random, x)

		return result
	except:
		return None

def bin2long(s):
	return reduce( lambda x,y:(x<<8L)+y, map(ord, s))

def long2bin(l):
	res = ""
	for byte in range(128):
		res += chr((l >> (1024 - (byte + 1) * 8)) & 0xff)
	return res

def rsa_pub1024(src, mod):
	return long2bin(pow(bin2long(src), 65537, bin2long(mod)))

def decrypt_block(src, mod):
	if len(src) != 128 and len(src) != 202:
		return None
	dest = rsa_pub1024(src[:128], mod)
	hash = hashlib.sha1(dest[1:107])
	if len(src) == 202:
		hash.update(src[131:192])
	result = hash.digest()
	if result == dest[107:127]:
		return dest
	return None

def tpm_check():
	try:
		tpm = eTPM()
		rootkey = ['\x9f', '|', '\xe4', 'G', '\xc9', '\xb4', '\xf4', '#', '&', '\xce', '\xb3', '\xfe', '\xda', '\xc9', 'U', '`', '\xd8', '\x8c', 's', 'o', '\x90', '\x9b', '\\', 'b', '\xc0', '\x89', '\xd1', '\x8c', '\x9e', 'J', 'T', '\xc5', 'X', '\xa1', '\xb8', '\x13', '5', 'E', '\x02', '\xc9', '\xb2', '\xe6', 't', '\x89', '\xde', '\xcd', '\x9d', '\x11', '\xdd', '\xc7', '\xf4', '\xe4', '\xe4', '\xbc', '\xdb', '\x9c', '\xea', '}', '\xad', '\xda', 't', 'r', '\x9b', '\xdc', '\xbc', '\x18', '3', '\xe7', '\xaf', '|', '\xae', '\x0c', '\xe3', '\xb5', '\x84', '\x8d', '\r', '\x8d', '\x9d', '2', '\xd0', '\xce', '\xd5', 'q', '\t', '\x84', 'c', '\xa8', ')', '\x99', '\xdc', '<', '"', 'x', '\xe8', '\x87', '\x8f', '\x02', ';', 'S', 'm', '\xd5', '\xf0', '\xa3', '_', '\xb7', 'T', '\t', '\xde', '\xa7', '\xf1', '\xc9', '\xae', '\x8a', '\xd7', '\xd2', '\xcf', '\xb2', '.', '\x13', '\xfb', '\xac', 'j', '\xdf', '\xb1', '\x1d', ':', '?']
		random = None
		result = None
		l2r = False
		l2k = None
		l3k = None

		l2c = tpm.getData(eTPM.DT_LEVEL2_CERT)
		if l2c is None:
			return 0

		l2k = validate_certificate(l2c, rootkey)
		if l2k is None:
			return 0

		l3c = tpm.getData(eTPM.DT_LEVEL3_CERT)
		if l3c is None:
			return 0

		l3k = validate_certificate(l3c, l2k)
		if l3k is None:
			return 0

		random = get_random()
		if random is None:
			return 0

		value = tpm.computeSignature(random)
		result = decrypt_block(value, l3k)
		if result is None:
			return 0

		if result [80:88] != random:
			return 0

		return 1
	except:
		return 0

def getAllInfo():
	info = {}

	brand = "unknown"
	model = "unknown"
	procmodel = "unknown"
	orgdream = 0
	if tpmloaded:
		orgdream = tpm_check()
# [IQON] brandtype and procmodel.
#	if fileExists("/proc/stb/info/hwmodel"):
#		brand = "DAGS"
        if fileExists("/proc/stb/info/modelname"):
		f = open("/proc/stb/info/modelname",'r')
		procmodel = f.readline().strip()
		f.close()

        if fileExists("/proc/stb/info/hwmodel"):
                f = open("/proc/stb/info/hwmodel",'r')
                model = f.readline().strip()
                f.close()
                
        if fileExists("/etc/.brandtype"):
                f = open("/etc/.brandtype",'r')
                brand = f.readline().strip().capitalize()
                f.close()



                # TODO : brandtype
#                remote = model
#               type = chipset...?
        if brand == "technomate":
                if model in ("tmnanooe", "tmsingle"):
                        remote = "te_type1"
                else:
                        if model in ("force1plus", "force2plus"):
                                remote = "te_type3"
                        elif model in ("force1", "tmnano2super"):
                                remote = "te_type2"
                        elif model in ("tmnanose", "tmnanosecombo"):
                                remote = "te_type3"
                        elif model in ("tmnanosem2", "tmnanoseplus"):
                                remote = "te_type4"
                        elif model in ("tmnanom3"):
                                remote = "tmnanom3"
                        else:
                                remote = "te_type0"
        elif brand == "swiss":
                if model in ("force1plus", "force1"):
                        remote = "sw_type0"
        elif brand == "edision":
                if model in ("force1plus"):
                        remote = "ed_type0"
                else:
                        if model in ("optimussos1plus", "optimussos2plus", "optimussos"):
                                remote = "ed_type1"
        elif brand == "worldvision":
                if model in ("force1plus", "force1", "force2", "force2solid"):
                        remote  = "wo_type0"
        elif brand == "xsarius":
                remote = model
        elif brand == "iqon":
                if model in ("force1plus", "force1"):
                        remote = "wo_type0"
                elif model in ("purehd"):
                        remote = model
                elif model in ("selfset"):
                        remote = model
                else:
                        remote = "iqon"
        else:
                remote = model
                        
#		if (procmodel.startswith("optimuss") or procmodel.startswith("pingulux")):
#			brand = "Edision"
#			model = procmodel.replace("optimmuss", "Optimuss ").replace("plus", " Plus").replace(" os", " OS")
#		elif (procmodel.startswith("fusion") or procmodel.startswith("purehd") or procmodel.startswith("revo4k") or procmodel.startswith("galaxy4k")):
#			brand = "Xsarius"
#			if procmodel == "fusionhd":
#				model = procmodel.replace("fusionhd", "Fusion HD")
#			elif procmodel == "fusionhdse":
#				model = procmodel.replace("fusionhdse", "Fusion HD SE")
#			elif procmodel == "purehd":
#				model = procmodel.replace("purehd", "PureHD")
#			elif procmodel == "revo4k":
#				model = procmodel.replace("revo4k", "Revo4K")
#			elif procmodel == "galaxy4k":
#				model = procmodel.replace("galaxy4k", "Galaxy4K")
	if fileExists("/etc/.box"):
		distro = "HDMU"
		f = open("/etc/.box",'r')
		tempmodel = f.readline().strip().lower()
		if tempmodel.startswith("ufs") or model.startswith("ufc"):
			brand = "Kathrein"
			model = tempmodel.upcase()
			procmodel = tempmodel
		elif tempmodel.startswith("spark"):
			brand = "Fulan"
			model = tempmodel.title()
			procmodel = tempmodel
		elif tempmodel.startswith("xcombo"):
			brand = "EVO"
			model = "enfinityX combo plus"
			procmodel = "vg2000"

	type = model

        #print "@@@@@@@@@@@@@ brand: (%s)" %(brand)
        #print "@@@@@@@@@@@@@ model: (%s)" %(model)
        #print "@@@@@@@@@@@@@ procmodel (%s)" %(procmodel)
        #print "@@@@@@@@@@@@@ type (%s)" %(type)
	info['brand'] = brand
	info['model'] = model
	info['procmodel'] = procmodel
	info['type'] = type

	info['remote'] = remote

	kernel = about.getKernelVersionString()[0]

	distro = "unknown"
	imagever = "unknown"
	imagebuild = ""
	driverdate = "unknown"

	# Assume OE 1.6
	oever = "OE 1.6"
	if kernel>2:
		oever = "OE 2.0"

	if fileExists("/etc/.box"):
		distro = "HDMU"
		oever = "private"
	elif fileExists("/etc/bhversion"):
		distro = "Black Hole"
		f = open("/etc/bhversion",'r')
		imagever = f.readline().strip()
		f.close()
		if kernel>2:
			oever = "OpenVuplus 2.1"
	elif fileExists("/etc/vtiversion.info"):
		distro = "VTi-Team Image"
		f = open("/etc/vtiversion.info",'r')
		imagever = f.readline().strip().replace("VTi-Team Image ", "").replace("Release ", "").replace("v.", "")
		f.close()
		oever = "OE 1.6"
		imagelist = imagever.split('.')
		imagebuild = imagelist.pop()
		imagever = ".".join(imagelist)
		if kernel>2:
			oever = "OpenVuplus 2.1"
		if ((imagever == "5.1") or (imagever[0] > 5)):
			oever = "OpenVuplus 2.1"
	elif fileExists("/var/grun/grcstype"):
		distro = "Graterlia OS"
		try:
			imagever = about.getImageVersionString()
		except:
			pass
	# ToDo: If your distro gets detected as OpenPLi, feel free to add a detection for your distro here ...
	else:
		# OE 2.2 uses apt, not opkg
		if not fileExists("/etc/opkg/all-feed.conf"):
			oever = "OE 2.2"
		else:
			try:
				f = open("/etc/opkg/all-feed.conf",'r')
				oeline = f.readline().strip().lower()
				f.close()
				distro = oeline.split( )[1].replace("-all","")
			except:
				pass

		if distro == "openpli":
			oever = "PLi-OE"
			try:
				imagelist = open("/etc/issue").readlines()[-2].split()[1].split('.')
				imagever = imagelist.pop(0)
				if imagelist:
					imagebuild = "".join(imagelist)
				else:
					# deal with major release versions only
					if imagever.isnumeric():
						imagebuild = "0"
			except:
				# just in case
				pass
		elif distro == "openrsi":
			oever = "PLi-OE"
		else:
			try:
				imagever = about.getImageVersionString()
			except:
				pass

		if (distro == "unknown" and brand == "Vu+" and fileExists("/etc/version")):
			# Since OE-A uses boxbranding and bh or vti can be detected, there isn't much else left for Vu+ boxes
			distro = "Vu+ original"
			f = open("/etc/version",'r')
			imagever = f.readline().strip()
			f.close()
			if kernel>2:
				oever = "OpenVuplus 2.1"

	# reporting the installed dvb-module version is as close as we get without too much hassle
	driverdate = 'unknown'
	try:
		driverdate = os.popen('/usr/bin/opkg -V0 list_installed *dvb-modules*').readline().split( )[2]
	except:
		try:
			driverdate = os.popen('/usr/bin/opkg -V0 list_installed *dvb-proxy*').readline().split( )[2]
		except:
			try:
				driverdate = os.popen('/usr/bin/opkg -V0 list_installed *kernel-core-default-gos*').readline().split( )[2]
			except:
				pass

	info['oever'] = oever
	info['distro'] = distro
	info['imagever'] = imagever
	info['imagebuild'] = imagebuild
	info['driverdate'] = driverdate

	return info

STATIC_INFO_DIC = getAllInfo()

def getMachineBuild():
	return STATIC_INFO_DIC['procmodel']

def getMachineBrand():
	return STATIC_INFO_DIC['brand']

def getMachineName():
	return STATIC_INFO_DIC['model']

def getMachineProcModel():
	return STATIC_INFO_DIC['procmodel']

def getBoxType():
	return STATIC_INFO_DIC['type']

def getOEVersion():
	return STATIC_INFO_DIC['oever']

def getDriverDate():
	return STATIC_INFO_DIC['driverdate']

def getImageVersion():
	return STATIC_INFO_DIC['imagever']

def getImageBuild():
	return STATIC_INFO_DIC['imagebuild']

def getImageDistro():
	return STATIC_INFO_DIC['distro']

class rc_model:
	def getRcFolder(self):
		return STATIC_INFO_DIC['remote']
