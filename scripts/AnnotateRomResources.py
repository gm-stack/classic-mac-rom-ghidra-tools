# Find ROM resources
# @author gm-stack
# @category MacRomHacking
#

###############
# imports
###############

import string
from collections import defaultdict, namedtuple

from ghidra.program.model.symbol.SourceType import * # todo: resolve what is actually used from here
from ghidra.program.model.data import ArrayDataType, EnumDataType, PointerTypedef, StructureDataType, CategoryPath, DataTypeConflictHandler, DataUtilities
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.database.data import TypedefDB
from ghidra.app.cmd.data import CreateArrayCmd
from ghidra.app.util.cparser.C import CParser


###############
# settings
###############

ROM_START_ADDR=0x40800000
ADDRESS_SPACE_NAME=None
BASE_CATEGORY_NAME='/ROMResources'
LABEL_PREFIX=''

###############
# Globals
###############

memory = currentProgram.getMemory()

reference_manager = currentProgram.getReferenceManager()

address_factory = currentProgram.getAddressFactory()
if ADDRESS_SPACE_NAME:
	address_space = address_factory.getAddressSpace(ADDRESS_SPACE_NAME)
	if not address_space:
		print("Address space %s not found!" % ADDRESS_SPACE_NAME)
		exit(1)
else:
	address_space = address_factory.getDefaultAddressSpace()

data_type_manager = currentProgram.getDataTypeManager()
base_category = CategoryPath(BASE_CATEGORY_NAME)
data_type_manager.createCategory(base_category)

###############
# Functions for creating data types
###############

# TODO: put into a common file

def subcategory_path(subcategory):
	# Returns a CategoryPath object for a subcategory that is a subfolder
	# inside the CategoryPath declared above
	# else if subcategory is None returns the base CategoryPath
	if subcategory:
		new_category = CategoryPath(base_category, subcategory)
		data_type_manager.createCategory(new_category)
		return new_category
	return base_category

def parseC(struct_txt, subcategory=None, packing=None):
	# Parses a string containing a C definition of a struct or enum
	# setting the category appropriately
	# and adding it into the Data Types manager
	parser = CParser(data_type_manager)
	parsed_datatype = parser.parse(struct_txt)
	if packing:
		parsed_datatype.setExplicitPackingValue(packing)
	parsed_datatype.setCategoryPath(subcategory_path(subcategory))
	return data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.REPLACE_HANDLER)

###############
# Creation of datatypes
###############

# probably only valid for machines with 18, 32, 60 in table above.
# Need to pull apart some other ROMs to figure out what's going on.
romHeader = parseC("""struct romHeader {
    ulong romID;
    pointer initialPC;
    byte machineNumber;
    byte romVersion;
    ulong jmpStartBoot;
    ulong jmpEjectAndReboot;
    word romRelease;
    byte romOverpatch;
    byte unused;
    ulong foreignOSTableOffset;
    ulong romResourceOffset;
    ulong jmpDoEject;
    ulong dispatchTableOffset;
    ulong jmpCriticalErr;
    ulong jmpResetEntryPoint;
    byte romInEmulator:1;
    byte romInRam:1;
    byte unused2;
    ulong checksum[4];
    ulong romSize;
};""", packing=1)

romHeaderRelativePtrs = [
    "foreignOSTableOffset",
	"romResourceOffset",
    "dispatchTableOffset"
]

foreignOSTable = parseC("""struct foreignOSTable {
    pointer InitDispatcher;
    pointer EMT1010;
    pointer BadTrap;
    pointer StartSDeclMgr;
    pointer InitMemVect;
    pointer SwitchMMU;
    // pointer InitRomVectors; // mentioned in source, not actually there
};""", packing=1)

extendedDeclRom = parseC("""struct extendedDeclRom {
    byte unused;
    int3 directory;
    byte unused2;
    int3 directoryEndSpace;
    ulong crc;
    byte romRevision;
    byte declRomFmt;
    ulong magic;
    byte reservedZero;
    byte byteLanes;
};""", packing=1) # TODO: turn packing off

###############
# Memory management
###############

def romAddr(addr):
	# returns an Address object for an offset into ROM
	# starting at ROM_START_ADDR in ADDRESS_SPACE_NAME
	target_addr = ROM_START_ADDR + addr
	return address_space.getAddressInThisSpaceOnly(target_addr)

def readDT(address,data_type,readfunc,sizemask):
	# Reads data from a memory location
	# ensuring Python treats as unsigned if necessary
	# by &'ing with FF
	data = readfunc(address)
	if sizemask: data = data & sizemask
	return data

read_uLong = lambda a: readDT(a, 'long', memory.getInt, 0xFFFFFFFF)	# 32 bit unsigned
read_int = lambda a: readDT(a, 'long', memory.getInt, None)			# 32 bit signed
read_uint3 = lambda a: readDT(a, 'uint3', memory.getInt, 0xFFFFFF)	# 24 bit unsigned
read_int3 = lambda a: readDT(a, 'int3', memory.getInt, None)		# 24 bit signed
read_uWord = lambda a: readDT(a, 'word', memory.getShort, 0xFFFF)	# 16 bit unsigned
read_uByte = lambda a: readDT(a, 'byte', memory.getByte, 0xFF)		# 8 bit unsigned

def forceSetDataType(addr, dtype):
	# Create data type at address
	# forcibly clearing out anything that was there already
	return DataUtilities.createData(
		currentProgram, addr, dtype, 0, 
		False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
	)

def structWithRelativePointers(ptr, structType, structRelativePointers):
	# Apply a struct to a memory address
	# setting appropriate x-refs for relative pointers
	# provided in a list
	struct = forceSetDataType(ptr, structType) # apply the struct
	struct_members = { c.getFieldName() : c for c in structType.getComponents() } # make lookup dict by struct component name
	
	for component in structRelativePointers:			# for each component in list of relative components
		component_member = struct_members[component]		# get which component, by name
		component_offset = component_member.getOffset() 	# offset for struct item from start of struct
		component_addr = ptr.add(component_offset)			# absolute address in memory of struct item
		component_dest_offset = read_int(component_addr)	# relative offset stored in struct item (relative to struct base)
		component_dest = ptr.add(component_dest_offset)		# derived absolute address that struct item is pointed to

		for ref in reference_manager.getReferencesFrom(component_addr): # clear out all other references including
			reference_manager.delete(ref)								# auto-generated ones
		
		dt_offset = 0										# assume default offset of 0 for pointer
		component_dt = component_member.getDataType()
		if type(component_dt) is TypedefDB:					# but if it's a typedef, there may be an offset
			component_offset_setting = {s.getName(): s for s in component_dt.getTypeDefSettingsDefinitions()}['Component Offset']
			dt_offset = component_offset_setting.getValue(component_member.getDefaultSettings())

		print("adding reference to %s (%i) %s -> %s +(0x%x)" % (component, component_offset, component_addr, component_dest, dt_offset))
		new_ref = reference_manager.addShiftedMemReference(
			component_addr, 					# from address
			component_dest.add(-dt_offset), 	# to address (shifted by data type offset, so struct points to start)
			dt_offset, 							# pointer offset shifted by (does Ghidra even use this?)
			RefType.DATA, 
			SourceType.USER_DEFINED, 
			0									# operand ID is 0 for data references
		)


###############
# The main part
###############

rom_base = romAddr(0x0)
structWithRelativePointers(rom_base, romHeader, romHeaderRelativePtrs)

foreign_table = romAddr(0x44)
forceSetDataType(foreign_table, foreignOSTable)

rom_top = memory.getRangeContaining(rom_base).getMaxAddress()
declRom_magic = rom_top.add(-5)
if not read_uLong(declRom_magic) == 0x5A932BC7L:
    print("declROM signature invalid, expected 0x5A932BC7 at %s" % declRom_magic)
    exit(1)
print("declRom magic found")

declRomPtr = rom_top.add(-extendedDeclRom.getLength() + 1)
forceSetDataType(declRomPtr, extendedDeclRom)

