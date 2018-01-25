from idaapi import *
from idc import *

#Find all potential Function Entry
OFFSET = 0
for i in Segments():
	start = i
	end = GetSegmentAttr(start, SEGATTR_END)
	addr = start
	while (addr != BADADDR):
		addr = FindBinary  (addr, SEARCH_DOWN, '2D E9', 16)
		if(addr != BADADDR ):
			addr = addr - 2
			if (addr%4) == OFFSET :
                                print "0x%X" % addr;
                                MakeCode(addr);
			addr = addr + 4

#Analyze
for i in Segments():
        start = i
        end = GetSegmentAttr(start, SEGATTR_END)
        AnalyzeArea(start, end)