import idautils

for x in idautils.Functions():
	funcName=GetFunctionName(x)
	if "___sub" in funcName:
		pos = funcName.find("___sub")
		newFuncName = funcName[pos+3:]
		firstFuncAddr = LocByName(funcName)
		MakeNameEx(firstFuncAddr, newFuncName, SN_NOWARN)
		#print(funcName + " to " + newFuncName)
	#E = list(FuncItems(x))
	#for e in E:
	#	print "%X"%e, GetDisasm(e)
	#tmp+=1
	#if tmp == 2:
	#	exit