###############
# imports
###############

import string
from collections import defaultdict

# this is the magic source of CurrentProgram and other variables
# that magically appear in your globals when you run a script directly
# inside Ghidra. But if you import a module you need to import this in the
# module or else those won't be there.
from __main__ import *

# import rest of Ghidra API
#from ghidra.program.model.symbol.SourceType import * # todo: resolve what is actually used from here

from ghidra.program.model.data import ArrayDataType, EnumDataType, PointerTypedef, \
									  StructureDataType, CategoryPath, DataTypeConflictHandler, \
									  DataUtilities
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.database.data import TypedefDB, StructureDB
from ghidra.app.util.cparser.C import CParser

def settings(start_addr, address_space_name, base_category_name, label_prefix):
	global ROM_START_ADDR
	global ADDRESS_SPACE_NAME
	global BASE_CATEGORY_NAME
	global LABEL_PREFIX

ROM_START_ADDR=0x0
ADDRESS_SPACE_NAME='_rom'
BASE_CATEGORY_NAME='/Misc'
LABEL_PREFIX='__'

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

def getDataType(dt_name):
	# returns a single data type - erroring if >1 definition or if not found
	dt = getDataTypes(dt_name)
	if len(dt) == 0: raise ValueError("data type %s not found" % dt_name)
	if len(dt) != 1: raise ValueError("data type %s has more than one definition" % dt_name)
	return dt[0]

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

def cleanup_identifier(dirty_name):
	# Cleans up a potentially dirty name into one 
	# that can be used as a C identifier, fixing:
	#  - leading numbers (leading _ added)
	#  - slash, space or brackets in the name (replaced with _)
	#  - plus signs in the name (replaced with 'plus')
	# This is by no means comprehensive...
	if dirty_name[0].isnumeric():
		dirty_name = '_' + dirty_name
	chars_to_replace = "/ ()"
	for c in chars_to_replace:
		dirty_name = dirty_name.replace(c, "_")
	dirty_name = dirty_name.replace("+","plus")
	return dirty_name

def array_to_enum(data, name, size, subcategory=None):
	# Takes a Python array and turns it into an enum
	# with the value being the position in the array, starting from 0
	# In case of duplicate values, an underscore is appended until it's unique
	# TODO: make a second pass and append the ID to all of them instead -
	#       that would be more useful
	already_included=set()
	enum = EnumDataType(subcategory_path(subcategory), name, size)
	for count, value in enumerate(data):
		clean_identifier = cleanup_identifier(value)
		while clean_identifier in already_included:
			clean_identifier += '_'
		already_included.add(clean_identifier)
		enum.add(clean_identifier, count)
	data_type_manager.addDataType(enum, DataTypeConflictHandler.REPLACE_HANDLER)

def createShiftedPointer(data_type, name, shift):
	# Creates a Ghidra shifted pointer for datatypes where
	# there are elements accessed before or after the pointer
	# This causes the decompiler to get the correct fields
	# when there are negative offsets
	shifted = PointerTypedef(name, data_type, -1, data_type_manager, shift)
	shifted.setCategoryPath(data_type.getCategoryPath()) # put it in same category as the source data type
	data_type_manager.addDataType(shifted, DataTypeConflictHandler.REPLACE_HANDLER)
	return shifted

def createStructWithArray(dt_name, count, name, componentName, subcategory=None):
	# Create a struct consisting only of a single array
	# made up of a specified data type and length.
	# Used to create struct for table of MachineInfo pointers
	dt = getDataType(dt_name)
	s = StructureDataType(subcategory_path(subcategory), name, 0)
	a = ArrayDataType(dt, count, 0)
	s.add(a, -1, componentName, None)
	return data_type_manager.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

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
read_uWord = lambda a: readDT(a, 'word', memory.getShort, 0xFFFF)	# 16 bit unsigned
read_uByte = lambda a: readDT(a, 'byte', memory.getByte, 0xFF)		# 8 bit unsigned

def resolveBaseType(ptr_type):
	# If it's a pointer, or typedef work out what 
	# it's a pointer to or a typedef of
	# and keep going until we get something not one of these two
	if type(ptr_type) is PointerDB:
		return resolveBaseType(ptr_type.getDataType())
	if type(ptr_type) is TypedefDB:
		return resolveBaseType(ptr_type.getDataType())
	return ptr_type

# TODO: need usefulArrayWrapper too, and probably a few other things!
class usefulStructWrapper(object):
	# allows you to assign a struct to a memory location with applyDataType
	# then read back the values of that struct:
	# s = applyDataType(someAddr, someStruct)
	# print(s.someField)
	
	def __init__(self, struct):
		self._struct = struct
		self._members = { 
			c.getFieldName() : c 
			for c in [
				struct.getComponent(cc) 
				for cc in range(struct.getNumComponents())
			]
		}

	def __getattr__(self, name):
		if name in self._members:
			m = self._members[name]
			# TODO: fix for more data types.
			dt = m.getDataType()
			primaryReference = m.getPrimaryReference(0)
			if primaryReference: # it's a pointer to somewhere else, with reference set. FIXME: it's just a normal pointer to somewhere else
				to_addr = primaryReference.getToAddress()
				dt = m.getDataType()
				dt = resolveBaseType(dt)
				wrapped = applyDataType(to_addr, dt) # FIXME: we should probably check it is a struct... otherwise return DefaultValueRepresentation
				return wrapped
			elif type(dt) is StructureDB: # FIXME: data.isStructure would work here?
				return usefulStructWrapper(m)
			else:
				return m.getDefaultValueRepresentation()
		raise AttributeError
	
	def __repr__(self): # print values as well as keys
		return "---\n" + "\n".join(str(m) for m in self._members) + "\n---"


def applyDataType(addr, dtype):
	# Create data type at address
	# forcibly clearing out anything that was there already
	# also wrap the returned structure if structure
	# TODO: CLEAR_ALL_CONFLICT_DATA does not actually clear all conflicts
	data =  DataUtilities.createData(
		currentProgram, addr, dtype, 0, 
		False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
	)
	if data.isStructure():
		return usefulStructWrapper(data)
	return data

def structWithRelativePointers(ptr, structType, structRelativePointers):
	# Apply a struct to a memory address
	# setting appropriate x-refs for relative pointers
	# provided in a list
	# TODO: store which pointers are relative *in* the struct somehow?
	struct = applyDataType(ptr, structType) # apply the struct
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
	return struct

###############
# Label Management
###############

managed_tables = defaultdict(lambda: defaultdict(set))

def add_managed_table(data_type, addr, key):
	# add a table to the list of tables to label
	# all key entries will be gathered for a certain address
	# if the table is referenced from multiple places
	# the label will name all of them
	# then the appropriate data type will be applied to each memory location
	managed_tables[data_type][addr].add(key)

def label_managed_tables():
	# create labels and force set data types as described above
	for dt, items in managed_tables.iteritems():
		for address, names in items.iteritems():
			label_name = cleanup_identifier(LABEL_PREFIX + dt.getName() + "_" + "_".join(names))
			print("labelling %s @ %s" % (label_name, address))
			createLabel(address, label_name, True)
			applyDataType(address, dt)
