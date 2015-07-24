buffer = {}
counter = 0
with open('V', 'r') as f:
    with open('Vt', 'w') as g:
        line = f.readline()
        while line:
            if line == "\n":
		for i in range(11):
		    for j in range(11):
			g.write(`buffer[j][i]` + " ")
		    g.write("\n")
		g.write("\n")
		line = f.readline()
		counter = 0
	    else:
		buffer[counter] = map(float,line.split())
		line = f.readline()
        	counter += 1
