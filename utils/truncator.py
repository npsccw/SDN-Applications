import argparse

def main():
	parser = argparse.ArgumentParser(description="cuts off bad portion of data")
	parser.add_argument("-f", "--file", dest="file", type=str, help="Enter file name")
	parser.add_argument("-t", "--time", dest="time", type=int,\
				 help="Enter time you want to chop off")
	parser.add_argument("-m", "--mode", dest="mode", default="value", type=str,\
				help="Designate vector or value file")
	parser.add_argument("-n", "--num_nodes", dest="num_nodes", default=11, type=int,\
				help="Enter the number of nodes in the network")
	args = parser.parse_args()
	truncate(args.file, args.time, args.mode, args.num_nodes)	
	

def truncate(file, time, mode, num_nodes):
	with open(file, "r") as f:
		lines = f.readlines()

	with open(file, "w") as f:
		if mode == "value":
			lines = lines[:time]
		
		elif mode == "vector":
			lines = lines[:(time*(num_nodes+1))]
		
		for line in lines:
			f.write(line)

		f.flush()



if __name__ == "__main__":
	main()

