before = open("Before/V", "r")
after = open("After/V", "r")
diff = open("diff1","w")
bline = before.readline()
aline = after.readline()
while aline and bline:
    if aline == "\n":
        aline = after.readline()
        bline = before.readline()
        diff.write("\n")
        continue
    aline = aline.split()
    bline = bline.split()
    for i in range(len(aline)):
        diff.write(`float(aline[i]) - float(bline[i])` + " ")
    diff.write("\n")
    aline = after.readline()
    bline = before.readline()

after.close()
before.close()
diff.flush()
diff.close()
