#!/usr/bin/env python
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import argparse

colors = {0:"BlueViolet", 1:"Black", 2:"Cyan", 3:"DarkGreen", 4:"DarkMagenta", 5:"DarkOrange",\
		6:"DarkGoldenRod", 7:"DeepPink", 8:"DarkSeaGreen", 9:"DodgerBlue", 10:"FireBrick"}

names = {0:'Chicago', 1:'Sunnyvale', 2:'Los Angeles', 3:'Salt Lake City', 4:'Denver',\
            5:'El Paso', 6:'D.C.', 7:'Kansas City', 8:'Seattle', 9:'Houston',\
             10:'Nashville'}

def plot(file="D",figure_no=1, start=0, end=270000, legend=True):
	fig = plt.figure(figure_no)
	ax = fig.add_subplot(111)

	plt.xlabel("Timestep")
	plt.ylabel("Eigenvalues")
	plt.title("Eigenvalues Over Time")
	fig.patch.set_facecolor("#E9E9E9")

	y = {}
	x = []
	lines = []
	for i in range(11):
    		y[i] = []

	with open(file,"r") as f:
    		counter = 0
		ln = 1
    		line = f.readline()
    		line = f.readline()
		for i in range(start):
			line = f.readline()
			counter += 1
    		while line and ln <= end-start:
        		line = map(float,line.split())
        		for i in range(1,11):
           			y[i].append(line[i])
        		x.append(counter)
        		counter += 1
        		line = f.readline()
			ln += 1

	for i in range(1,11): 
    		line, = plt.plot(x,y[i], color=colors[i], label="$\\lambda$"+`i+1`)
    		lines.append(line)

	y_max = max([max(y[i]) for i in range(1,11)])+5 
	y_min = min([min(y[i]) for i in range(1,11)])-5
	x_max = max(x)
	x_min = min(x)
	plt.ylim(y_min,y_max)
	plt.xlim(x_min,x_max)
	if legend:
		plt.legend(handles=lines)
	plt.show()
	plt.pause(2)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Plots the eigenvalues between time intervals")
	parser.add_argument('-s', '--start', dest='start', type=int, default=0, \
			help='Enter the time you want to start plotting at')
	parser.add_argument('-e', '--end', dest='end', type=int, default=27000000000,\
			help='Enter the time you want to stop plotting at')
	parser.add_argument('-f', '--file', dest='file', type=str, default='D',\
			help='Specify file to plot')
	args = parser.parse_args()
	plot(file=args.file, start=args.start//2, end=args.end//2, legend=False)





