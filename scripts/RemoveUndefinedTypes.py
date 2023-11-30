# Clean up undefined references to data types from ROM.
#@author gm-stack
#@category MacRomHacking

from ghidra.program.model.symbol import *

MEMORY_MAP_NAME="_rom"

currentProgram = getCurrentProgram()
af = currentProgram.getAddressFactory()
addrsp = af.getAddressSpace(MEMORY_MAP_NAME)
cleanup_names = ['undefined1', 'undefined2', 'undefined4', 'undefined *']

for i in xrange(0x000fffff):
	addrInSpace = addrsp.getAddressInThisSpaceOnly(i)
	data_ref = getDataAt(addrInSpace)
	if data_ref:
		data_name = data_ref.getDataType().getName()
		if data_name in cleanup_names and not getReferencesTo(addrInSpace):
			removeData(data_ref)
	
