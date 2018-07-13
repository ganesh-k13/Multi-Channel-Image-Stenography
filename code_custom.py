from PIL import Image
import binascii
import optparse
from pprint import pprint

def rgb2hex(r, g, b):
	return '#{:02x}{:02x}{:02x}'.format(r, g, b)

def hex2rgb(hexcode):
	return tuple(binascii.unhexlify(hexcode[1:]))

def str2bin(message):
    binary = bin(int(binascii.hexlify(message.encode("ascii")), 16))
    return binary[2:]

def bin2str(binary):
	message = binascii.unhexlify('%x' % (int('0b'+binary.strip(),2)))
	# message = binary
	return message

def encode(hexcode, digit):
	if hexcode[-1] in ('0','1', '2', '3', '4', '5'):
		hexcode = hexcode[:-1] + digit
		return hexcode
	else:
		return None

def decode(hexcode):
	if hexcode[-1] in ('0', '1'):
		return hexcode[-1]
	else:
		return None

def gen_seq(n):
	seq = list()
	for i in range(n):
		row = [i+j for j in range(0, 10000, n)]
		seq.append(row)
	return seq	
	
def hide(filename, messages, n):
	seq = gen_seq(n)
	img = Image.open(filename)
	binarys = [str2bin(m) + '1101111111111110' for m in messages]
	if img.mode in ('RGBA'):
		img = img.convert('RGBA')
		datas = img.getdata()
		newData = []
		temp = ''
		digit = [0 for i in range(n)]
		for i, item in enumerate(datas):
			# print(i)
			isAppended = False
			for j in range(n):
				if (digit[j] < len(binarys[j]) and i in seq[j]):
					newpix = encode(rgb2hex(item[0], item[1], item[2]), binarys[j][digit[j]])
					if newpix == None:
						newData.append(item)
					else:
						r, g, b = hex2rgb(newpix)
						newData.append((r,g,b,255))
						digit[j] += 1
					isAppended = True
					break
					# print("if", i)
			if(isAppended == False):
				newData.append(item)
				isAppended = True
		img.putdata(newData)
		img.save(filename, "PNG")
		return "Completed!"
			
	return "Incorrect Image Mode, Couldn't Hide"

def retr(filename, seq):
	img = Image.open(filename)
	binary = ''
	
	if img.mode in ('RGBA'): 
		img = img.convert('RGBA')
		datas = img.getdata()
		
		for i, item in enumerate(datas):
			digit = decode(rgb2hex(item[0],item[1],item[2]))
			if digit == None:
				pass
			elif(i in seq):
				binary = binary + digit
				if (binary[-16:] == '1101111111111110'):
					print("Success")
					return bin2str(binary[:-16])

		return bin2str(binary)
	return "Incorrect Image Mode, Couldn't Retrieve"

def Main():
	parser = optparse.OptionParser('usage %prog '+\
	'-e/-d <target file>')
	parser.add_option('-e', dest='hide', type='string', \
		help='target picture path to hide text')
	parser.add_option('-d', dest='retr', type='string', \
		help='target picture path to retrieve text')
	parser.add_option('-n', dest='n', type='int', \
		help='Number of channels')
	parser.add_option('-u', dest='u', type='int', \
		help='User Number')
	(options, args) = parser.parse_args()
	if (options.hide != None):
		texts = input("Enter a messages to hide(sep=':'): ").split(':')[:options.n]
		print(hide(options.hide, texts, options.n))
	elif (options.retr != None):
		seq = [(options.u-1)+j for j in range(0, 1000, options.n)]
		print(retr(options.retr, seq))
	else:
		print(parser.usage)
		exit(0)

if __name__ == '__main__':
	# print(gen_seq(2)[0])
	Main()

'''
Single Decode:
real    0m0.247s
user    0m0.063s
sys     0m0.078s

Multiple Encode:
real    1m08.610s
user    1m06.688s
sys     0m1.125s

Single Encode:
real    0m9.217s
user    0m3.672s
sys     0m1.672s

'''