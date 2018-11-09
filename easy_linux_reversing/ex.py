v8 = ['C', 'f', 'D', 'Z', 'q', 'B', 'r', 'p', 'R', 'W', 'j', '1', 'z']
test = [222, -125, 83, -115, -116, -79, 189, -105, 195, 145, 211, 37, 208]
v10 = ['T', 'z', '1', 'j', 'W', 'R', 'p', 'r', 'B', 'q', 'Z', 'D', 'f']

v8_1 = [] # ord(v8)
v10_1 = [] # ord(v10) + i 
and_v10 = [] # v10+i & 1
xor_v8 = [] # XOR V8
v10_ord =[] # ord(v10)

for i in range(13):
	result1 = ord(v8[i]) # v8_1 -> ord
	v8_1.append(result1)

	result2 = ord(v10[i]) # v10_ord -> ord
	v10_ord.append(result2)
	result2 += i          # v10_1 = v10_ord + i 
	v10_1.append(result2)

	result3 = v10_1[i] & 1 # and_v10 = v10_1[i] & 1
	and_v10.append(result3)

	result4 = v8_1[i] ^ test[i] # xor_v8 = v8_1[i] ^ v10+v7-i
	xor_v8.append(result4)

flag = []
chr_flag = ''

for i in range(13):
	if and_v10[i] == 1:
		result = v10_ord[i] + xor_v8[i]
		flag.append(result)
	elif and_v10[i] == 0:
		result = xor_v8[i] - v10_ord[i]
		flag.append(result)
print flag

for i in range(13):
	try:
		chr_flag += chr(flag[i])
	except:
		pass

print chr_flag
