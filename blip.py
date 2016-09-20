import os


def getFiles(text):
	for fname in os.listdir('../bl/'):    # change directory as needed
		if os.path.isfile(fname):    # make sure it's a file, not a directory entry
			with open(fname) as f:   # open file
				for line in f:       # process line by line
					if  text in line:    # search for string
						print 'found string in file %s' %fname
						break
