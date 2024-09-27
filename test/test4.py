import time
a=1
start=time.clock()
for i in range(10000):
	file=open('python','r+w')
	file.write("1")
	file.close()
end=time.clock()
print("Running time: %s Seconds"%(end-start))
