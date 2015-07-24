import argparse
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser(description="Plots bar graphs")
parser.add_argument('file', metavar="F", type=str, help="enter the file name")

args = parser.parse_args()
ind = np.arange(11)
width = .85

with open(args.file,"r") as f:
    line = map(float,f.readline().split())
fig, ax = plt.subplots()
rects = ax.bar(ind, line, width, color='b')
ax.set_ylabel("Index Value")
ax.set_xlabel("Vector Index")
ax.set_title("Eigenvector values for vector " + args.file[0])
ax.set_xticks(ind+width/2)
ax.set_xticklabels(tuple([i for i in range(11)]))    
plt.ylim((0,.45))
plt.xlim((0,11))
fig.patch.set_facecolor('#E9E9E9')
plt.show()
