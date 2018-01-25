import idautils

#http://hooked-on-mnemonics.blogspot.fr/2012/07/renaming-subroutine-blocks-and.html
#https://www.hex-rays.com/products/ida/support/idadoc/162.shtml

def ren_func_containing_addr( addr, newFuncName ):
	#print(func_ref)
	oriFuncName = GetFunctionName(addr)
	firstFuncAddr = LocByName(oriFuncName)
	fullFuncName = newFuncName + "___" + oriFuncName
	print(fullFuncName)
	# dont rename if already renamed
	if "sub_" not in oriFuncName[4:]:
		MakeNameEx(firstFuncAddr, fullFuncName, SN_NOWARN)

		
def ren_func_with_str( strAddr, newFuncName ):
	# Get all code xrefs to
	ref_addr = DataRefsTo(strAddr)
	# For each code xrefs to is not in nodes 
	for func_ref in ref_addr:
		ren_func_containing_addr(func_ref, newFuncName)

		
s = idautils.Strings(False)
s.setup(strtypes=Strings.STR_UNICODE | Strings.STR_C)
for i, v in enumerate(s):
    if v is None:
        print("Failed to retrieve string index %d" % i)
    else:
		theString = str(v)
		if "Enter:" in theString:
			funcName = theString[7:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			#print("%x: len=%d type=%d index=%d-> '%s'" % (v.ea, v.length, v.type, i, funcName))
			ren_func_with_str(v.ea, funcName)
		if "[IMEI] oem_" in theString:
			funcName = theString[7:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)	
		if "[C-AT]Cat_" in theString:
			funcName = theString[6:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)	
		if "[C-AT]cat_" in theString:
			funcName = theString[6:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)	
		if "[Call]Oem" in theString:
			funcName = theString[6:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)				
		if "[MISC] oem_" in theString:
			funcName = theString[7:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)	
		if "[Net]Oem" in theString:
			funcName = theString[5:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)			
		if "[OemSim] : oem_" in theString:
			funcName = theString[11:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)				
		if "[RFS]oem_" in theString:
			funcName = theString[5:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)	
		if "[RFS]rfs_" in theString:
			funcName = theString[5:]
			pos = funcName.find(" ")
			if pos > 0: funcName = funcName[:1*pos-len(funcName)]
			ren_func_with_str(v.ea, funcName)					
		if "OemSSSecureBlockEncWrite" in theString:
			ren_func_with_str(v.ea, "OemSSSecureBlockEncWrite")
		if "There is secure block" in theString:
			ren_func_with_str(v.ea, "READ_EFS_V1_V2")
		if "Error writing message length" in theString:
			ren_func_with_str(v.ea, "LOG_MESSAGE")
		if "func_exec_function" in theString:
			ren_func_with_str(v.ea, "func_exec_function")
		if "func_malloc" in theString:
			ren_func_with_str(v.ea, "func_malloc")
		if "func_process_running" in theString:
			ren_func_with_str(v.ea, "func_process_running")
		if "func_sec_process" in theString:
			ren_func_with_str(v.ea, "func_sec_process")
		if "OEM_NVM_IMEI_CERTIFICATE_SIGNATURE" in theString:
			ren_func_with_str(v.ea, "VALIDATE_IMEI_CERT")
		if "Error: Key cannot be calculated" in theString:
			ren_func_with_str(v.ea, "SEC_BLOCK_READ_WRITE")
		
# Guessed functions
pos = idc.FindBinary(0, 1, "0B 99 04 AA 06 A8 02 F0 A8 F9 00 20")
if pos != idc.BADADDR:
	ren_func_containing_addr(pos, "DECRYPT_BLOCK")
pos = idc.FindBinary(0, 1, "0B 99 04 AA 06 A8 02 F0 72 F9 08 99")
if pos != idc.BADADDR:
	ren_func_containing_addr(pos, "ENCRYPT_BLOCK")
pos = idc.FindBinary(0, 1, "04 49 CA 6E 02 60 0A 6F")
if pos != idc.BADADDR:
	ren_func_containing_addr(pos, "GET_SCU_SERIAL")
pos = idc.FindBinary(0, 1, "32 46 29 46 20 46 DB F0 CB FE 02 4A")
if pos != idc.BADADDR:
	ren_func_containing_addr(pos, "DO_SEC_BLOCK_READ_WRITE")	
pos = idc.FindBinary(0, 1, "F6 F7 A1 F8 02 90 20 46 F6 F7 CF F8")
if pos != idc.BADADDR:
	ren_func_containing_addr(pos, "READ_NV_PARAM")				
			
		#if "[SEC] SECSBLK" in theString:
		#	funcName = theString[6:]
		#	pos = funcName.find(" ")
		#	if pos > 0: funcName = funcName[:1*pos-len(funcName)]
		#	#print("%x: len=%d type=%d index=%d-> '%s'" % (v.ea, v.length, v.type, i, funcName))
		#	ren_func_with_str(v.ea, funcName)