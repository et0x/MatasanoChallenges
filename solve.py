#!/usr/bin/python

from Crypto.Cipher import AES

import base64
import binascii
import collections
import itertools

def pad_hex(hex):
	"""	append a leading '0' to hex strings if the length isn't correct """
	lead = '0'*(len(hex)%2)
	return lead+hex

def hex_to_base64(hex):
	hex = pad_hex(hex)
	return base64.b64encode(hex.decode("hex"))

def xor_hex(hex1,hex2):
	""" results returned as a hex string """
	str1 = pad_hex(hex1).decode("hex")
	str2 = pad_hex(hex2).decode("hex")
	return pad_hex("".join(hex(ord(i) ^ ord(j))[2:].zfill(2) for i,j in zip(str1,str2)))

def xor_hex_byte(hex,byte):
	""" feed in hex and character """
	hex = pad_hex(hex)
	dataLen = len(hex.decode("hex"))
	bytes = byte * dataLen
	hexBytes = pad_hex(bytes.encode("hex"))
	xored = xor_hex(hex,hexBytes)
	return xored

def xor_hex_repeatingKey(hexData,hexKey):
	hexData = pad_hex(hexData)
	dataLen = len(hexData.decode("hex"))
	rawKey = pad_hex(hexKey).decode("hex")
	rawData = pad_hex(hexData).decode("hex")
	key = (rawKey * (len(rawData) / len(rawKey))) + rawKey[:len(rawData)%len(rawKey)]
	key = pad_hex(key.encode("hex"))
	return xor_hex(hexData,key)

def chunk_data(hexData,chunkSize):
	""" return a list of chunks from data, n size in length
	    ex: chunk_data('41424344',2) becomes ['4142','4344']"""
	chunkList = []
	hexData = pad_hex(hexData)
	rawData = hexData.decode("hex")
	dataLen = len(rawData)
	for i in range(0,dataLen,chunkSize):
		chunk = rawData[i:i+chunkSize]
		chunk = chunk.encode("hex")
		chunk = pad_hex(chunk)
		chunkList.append(chunk)
	return chunkList

def chunk_list_to_tuple_list(chunkList):
	""" return a list of tuples of chunks
		ex: ["4142","4344","4546","4748"] 
		becomes [('4142', '4344'), ('4546', '4748')]"""
	tupleList = []
	for i in range(0,len(chunkList),2):
		try:
			tupleList.append((chunkList[i],chunkList[i+1]))
		except IndexError:
			break
	return tupleList

#################################################
##            Hamming Distance                 ##
#################################################

def hex_to_bin(hexStr):
	hexStr = pad_hex(hexStr)
	rawStr = hexStr.decode("hex")
	return "".join(bin(ord(x))[2:].zfill(8) for x in rawStr)

def hamming_distance(bin1,bin2):
	distance = 0
	for i,j in zip(bin1,bin2):
		if i != j:
			distance += 1
	return distance

#################################################
##          Character Frequency Scoring        ##
#################################################
def score_data(hexData):
	""" returns the score of a block of data """
	englishLetterFreq = {
						 'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
						 'S': 6.33,  'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
						 'U': 2.76,  'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 
						 'P': 1.93,  'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 
						 'Q': 0.10,  'Z': 0.07, ' ': 20}
	finalScore = 0
	rawData = pad_hex(hexData).decode("hex")
	for byte in rawData:
			if byte.upper() in englishLetterFreq.keys():
				finalScore += englishLetterFreq[byte.upper()]
			else:
				finalScore -= 30
	return finalScore

def find_single_byte_xor(hexData):
	""" goes through all 255 ASCII characters, returns ((hex str)key ,(hex str)xoredData) with highest score """
	# scores = {SCORE:'key'}
	hexData = pad_hex(hexData)
	scores = {}
	xoredData = ""
	score = 0
	for key in range(256):
		xoredData = xor_hex_byte(hexData,chr(key))
		score = score_data(xoredData)
		scores[score] = hex(key)[2:].zfill(2)
	xorByte = int(scores[sorted(scores.keys())[::-1][0]],16)
	xorChr = chr(xorByte)
	return hex(xorByte)[2:].zfill(2),xor_hex_byte(hexData,xorChr)

def find_single_byte_xor_list(hexList):
	""" feed in a list of hex strings, return highest scoring result """
	""" returns (score, hexkey, hexdata) """
	resultsList = []
	topScore = 0
	topScoreData = ""
	topScoreKey = ""

	for hexString in hexList:
		hexString = hexString.strip()
		key,value = find_single_byte_xor(hexString)
		resultsList.append((key,value))

	for k,v in resultsList:
		tmp = score_data(v)
		if tmp > topScore:
			topScore = tmp
			topScoreData = v
			topScoreKey = k

	return topScore, topScoreKey, pad_hex(topScoreData)

def guess_keysizes(hexData, n, maxKeySize):
	""" return the top n lowest hamming distances for keys
		up to size maxKeySize"""
	rawData = binascii.unhexlify(hexData)
	dataLen = len(rawData)
	finalDict = {}
	returnList = []

	for keySize in range(2,maxKeySize+1):
		hammingDistances = []
		dataChunks = chunk_data(hexData, keySize)
		chunkTupleList = chunk_list_to_tuple_list(dataChunks)
		for chunkTuple in chunkTupleList:
			hammingDistances.append(float(hamming_distance(chunkTuple[0],chunkTuple[1]))/keySize)
		finalDict[sum(hammingDistances)/len(hammingDistances)] = keySize

	for i in range(n):
		returnList.append(finalDict[sorted(finalDict.keys())[i]])

	return returnList



def zip_list(lst):
	""" takes in a list of tuples and returns a new list containing
		items with the nth character of each list item 
		ex: ['abc','def','ghi'] returns ['adg','beh','cfi']"""
	finalList = []
	rawList = []
	for i in lst:
		rawList.append(i.decode("hex"))
	for i in itertools.izip_longest(*rawList,fillvalue="\x00"):
		finalList.append("".join(x for x in i).encode("hex"))
	return finalList

#################################################
##                    AES                      ##
#################################################

class AESCipher_ECB:
	def __init__(self,key):
		self.key = key
		self.BLOCK_SIZE = 16

	def __pad(self,hexData):

		raw = binascii.unhexlify(hexData)

		if (len(raw) % self.BLOCK_SIZE == 0):
			return hexData
		else:
			padding_required = self.BLOCK_SIZE - (len(raw) % self.BLOCK_SIZE)
			padChar = "\x00"
			data = raw.encode('utf-8') + padding_required * padChar
			return data

	def __unpad(self, s):
		s = s.rstrip("\x00")
		return s

	def encrypt(self, hexData):
		raw = self.__pad(hexData)
		cipher = AES.AESCipher(self.key[:32], AES.MODE_ECB)
		ciphertext = cipher.encrypt(raw)
		return binascii.hexlify(bytearray(ciphertext)).decode("utf-8")

	def decrypt(self, hexData):
		raw = binascii.unhexlify(hexData)
		cipher = AES.AESCipher(self.key[:32], AES.MODE_ECB)
		raw = self.__unpad(cipher.decrypt(raw))
		return binascii.hexlify(raw.decode("utf-8"))

###############################################################################
# set 1 challenge 1:
# print hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
###############################################################################
# set 1 challenge 2:
# print xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
###############################################################################
# set 1 challenge 3:
# data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
# key,data = find_single_byte_xor(data)
# print "XOR Key: 0x%s"%key
# print "--------------"
# print data.decode("hex")
###############################################################################
# set 1 challenge 4:
#datas = open("1-4.txt").readlines()
#score,key,data = find_single_byte_xor_list(datas)
#print "Score: %d, Key: 0x%s"%(score,key)
#print "----------------------"
#print data.decode("hex")
###############################################################################
# set 1 challenge 5:
# key = "ICE".encode("hex")
# data = "Burning 'em, if you ain't quick and nimble\n"
# data += "I go crazy when I hear a cymbal"
# data = data.encode("hex")
# print xor_hex_repeatingKey(data,key)
###############################################################################
# set 1 challenge 6:
# data = open("1-6.txt").read()
# data = binascii.hexlify(base64.b64decode(data))
# keySizes = guess_keysizes(data,1,40)
#
# finalKey = ""
# for keySize in keySizes:
# 	finalKey = ""
#	dataChunks = chunk_data(data,keySize)
#	dataChunks = zip_list(dataChunks)
#	for chunk in dataChunks:
#		finalKey += find_single_byte_xor(chunk)[0].decode("hex")
# finalKeyHex = binascii.hexlify(finalKey)
# print "Key: '%s'"%(finalKey)
# print "="*(len(finalKey)+7)
# print xor_hex_repeatingKey(data,finalKeyHex).decode("hex")

###############################################################################
# set 1 challenge 7:
# data = open("1-7.txt").read()
# data = binascii.hexlify(base64.b64decode(data))
# c = AESCipher_ECB("YELLOW SUBMARINE")
# print binascii.unhexlify(c.decrypt(data))
