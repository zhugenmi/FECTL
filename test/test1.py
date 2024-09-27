import time
a=1
start=time.clock()
for i in range(1000000):
	a=a+i
end=time.clock()
print("Running time: %s Seconds"%(end-start))
