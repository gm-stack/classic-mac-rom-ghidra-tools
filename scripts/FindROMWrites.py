# Find accesses to memory from overlay ROM, point them at RAM under overlay ROM
# Overlay ROM exists only at early boot, so is unlikely to be the source of most memory accesses
#@author gm-stack
#@category MacRomHacking

from ghidra.program.model.symbol import *

MEMORY_MAP_NAME="_rom"
TYPES_TO_MODIFY = [ RefType.WRITE ] #, RefType.READ, RefType.READ_WRITE ]

currentProgram = getCurrentProgram()
af = currentProgram.getAddressFactory()
addrsp = af.getAddressSpace(MEMORY_MAP_NAME)

for i in xrange(0x000fffff): # FIXME: detect ROM length
	addrInSpace = addrsp.getAddressInThisSpaceOnly(i)
	refs = getReferencesTo(addrInSpace)
	for ref in refs:
		if ref.getReferenceType() in TYPES_TO_MODIFY:
			print(ref)
			inst = getInstructionAt(ref.getFromAddress())
			realToAddr = toAddr(addrInSpace.toString(False)) # there is probably a better way of doing that

			removeReference(ref)
			createMemoryReference(inst, ref.getOperandIndex(), realToAddr, ref.getReferenceType())

