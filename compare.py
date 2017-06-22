import sys

if len(sys.argv) < 3:
	print("Usage: compare.py file1 file2")
	exit(0)

f1file = open(sys.argv[1], "rb")
f2file = open(sys.argv[2], "rb")

result = 0
lcount = 0
for line in f1file.readlines():
	lcount +=1
	count = 0
	split = line.split(" ")
	for f2line in f2file.readlines():
		count = 0
		for word in split:
			if not word.lower() in ["is", "of", "to", "and", "the", "or"]:
				if word.lower().strip() in f2line.lower():
					count +=1
		if count > 0:
			print ("%s: %s vs. %s" % (str(count), line, f2line.lower()))
			result += 1
print("%s vs %s" % (sys.argv[1], sys.argv[2]))
print("Lines: %s / Matches: %s" % (str(lcount),str(result)))		
