"""
This file takes the data rates collected from the CCW
SDN.  These function are made specifically for CCW, so
major modification is required to generalize this.
"""
import numpy as np
import matplotlib.pyplot as plt
from Link import Link
from numpy import matlib
from multiprocessing import Process, Pipe
from operator import attrgetter
from datetime import datetime

class Analyzer:

        def __init__(self):
                self.timestep = 1
                self.dpid_to_node = {0x00012c59e5107640:1, 0x0001c4346b94a200:2,\
                                         0x0001c4346b99dc00:4, 0x0001c4346b946200:5,\
                                         0x0001c4346b971ec0:6, 0x0001f0921c219d40:13}

                self.name_to_index = {1:0, 2:1, 3:2, 4:3, 5:4, 6:5, 8:6, 11:7, 12:8,\
                                        13:9, 14:10}
                self.colors = {0:"Blue", 1:"BlueViolet", 2:"CadetBlue", 3:"Coral", 4:"DarkGreen",\
                                5:"DarkGoldenRod", 6:"DarkRed", 7:"DarkTurquoise",\
                                 8:"DarkOliveGreen", 9:"DeepSkyBlue", 10:"FireBrick"}
                self.names = {0:'Chicago', 1:'Sunnyvale', 2:'Los Angeles', 3:'Salt Lake City', 4:'Denver',\
                                5:'El Paso', 6:'D.C.', 7:'Kansas City', 8:'Seattle', 9:'Houston',\
                                10:'Nashville'}
                self.links = {(1,14):Link(1,14), (1,8):Link(1,8),\
                                (1,11):Link(1,11), (1,12):Link(1,12),\
                                (2,3):Link(2,3), (2,12):Link(2,12),\
                                (4,5):Link(4,5), (4,3):Link(4,3),\
                                (4,12):Link(4,12), (5,11):Link(5,11),\
                                (5,6):Link(5,6), (6,13):Link(6,13),\
                                (6,3):Link(6,3), (13,14):Link(13,14)}

                self.disconnected_links = set([(2,3), (6,3), (1,11), (13,14)])
                for link in self.disconnected_links:
                        self.links[link].updated = True

                self.times = []
                self.evalues = {0:[], 1:[], 2:[], 3:[], 4:[], 5:[], 6:[],\
                                7:[], 8:[], 9:[], 10:[]}
                self.lines = [0,0,0,0,0,0,0,0,0,0,0]
                adj = self.create_adj()
                L = matlib.zeros((11,11))
                np.fill_diagonal(L, np.array(sum(adj)))
                L -= adj
                self.initialL = L

                #Create a separate plotting thread for online plotting
                self.parent_conn, child_con = Pipe()
                self.plotting_thread = Process(target=self.plot, args=(child_con, ))
                self.plotting_thread.start()


        def analyze(self, ev, time):
                switch = self.dpid_to_node[ev.msg.datapath.id]
                for stat in sorted(ev.msg.body, key=attrgetter('port_no')):
                        port, rx_b, tx_b = stat.port_no, stat.rx_bytes, stat.tx_bytes
                        if (switch,port) in self.links and (switch,port) not in\
                            self.disconnected_links:
                                link = self.links[(switch,port)]
                                link.elapse_time([rx_b, tx_b], time)
                                link.updated = True

                all_updated = True
                for link in self.links:
                        if not self.links[link].updated:
                                all_updated = False
                                break

                if all_updated:
                        self.spectral_analysis()

                        for link in self.links:
                                if link not in self.disconnected_links:
                                        self.links[link].updated = False
                        self.timestep += 1

        def spectral_analysis(self):
                data = []
                adj = self.create_adj()
                L = matlib.zeros((11,11))
                np.fill_diagonal(L, np.array(sum(adj)))
                L -= adj
                Dnow, Vnow = np.linalg.eig(L)
                idx = Dnow.argsort()
                Dnow = Dnow[idx]
                Vnow = Vnow[:,idx]
                self.times.append(self.timestep)
                data.append(self.timestep)
                data.append({})
                for i in range(11):
                        self.evalues[i].append(Dnow[i])
                        data[1][i] = Dnow[i]
                self.write_matrix(Vnow, "V")
                self.write_value(Dnow)
                self.write_matrix(L, "L")
                self.parent_conn.send(data)

        def create_adj(self):
                adj = matlib.zeros((11,11))
                for link in self.links:
                        link = self.links[link]
                        adj[self.name_to_index[link.src],self.name_to_index[link.dst]] =\
                                link.weight
                        adj[self.name_to_index[link.dst],self.name_to_index[link.src]] =\
                                link.weight
                return adj

        def write_matrix(self, matrix, file_name):
                f = open(file_name, "a")
                for vect in matrix:
                        for i in range(11):
                               f.write(`vect[(0,i)]` + " ")
                        f.write("\n")
                f.write("\n")
                f.flush()
                f.close()

        def write_value(self, valuesIn):
                values = open("D", "a")
                for value in valuesIn:
                        values.write(`value` + " ")
                values.write("\n")
                values.flush()
                values.close()

        def plot(self, child_con):
            times = []
            evalues = {0:[], 1:[], 2:[], 3:[], 4:[], 5:[], 6:[],\
                        7:[], 8:[], 9:[], 10:[]}
            lines = [0,0,0,0,0,0,0,0,0,0,0]
            colors = {0:"Blue", 1:"BlueViolet", 2:"CadetBlue", 3:"Coral", 4:"DarkGreen",\
                                5:"DarkGoldenRod", 6:"DarkRed", 7:"DarkTurquoise",\
                                 8:"DarkOliveGreen", 9:"DeepSkyBlue", 10:"FireBrick"}
            names = {0:'Chicago', 1:'Sunnyvale', 2:'Los Angeles', 3:'Salt Lake City', 4:'Denver',\
                                5:'El Paso', 6:'D.C.', 7:'Kansas City', 8:'Seattle', 9:'Houston',\
                                10:'Nashville'}

            while True:
                try:
                    data = child_con.recv()

                    times.append(data[0])
                    for i in range(11):
                        evalues[i].append(data[1][i])
                    if len(times) > 20:
                            times.pop(0)
                            for i in range(11):
                                evalues[i].pop(0)
                    plt.xlim(min(times),max(times))
                    ys = [max(evalues[i]) for i in range(11)]
                    plt.ylim(-5, max(ys)+5)
                    for i in range(11):
                            line, = plt.plot(times, evalues[i],\
                                        color=colors[i], label=names[i])
                            lines[i] = line

                    plt.legend(handles=lines)
                    #plt.draw()
                    plt.pause(2)
                    for line in lines:
                            line.remove()
                except IOError:
                    continue

