writer = open('filename_original.txt', 'w')
reader = open('filename.txt', 'r')

line_read = reader.readline()

while line_read:
	print(line_read)
	if 'Content' not in line_read and 'Forked' not in line_read:
		writer.write(line_read)
	line_read = reader.readline()
