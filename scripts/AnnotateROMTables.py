# Find the machine table in an old world ROM image and annotate with comments, labels, references and data types
# @author gm-stack - initial values for rom_offsets and some names stolen from rb6502's unirom https://github.com/rb6502/unirom
# @category MacRomHacking
#

###############
# imports
###############

import string
from collections import defaultdict

from ghidra.program.model.symbol.SourceType import * # todo: resolve what is actually used from here
from ghidra.program.model.data import ArrayDataType, EnumDataType, PointerTypedef, StructureDataType, CategoryPath, DataTypeConflictHandler, DataUtilities
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.program.database.data import TypedefDB
from ghidra.app.cmd.data import CreateArrayCmd
from ghidra.app.util.cparser.C import CParser


###############
# settings
###############

#ROM_START_ADDR=0x0
#ADDRESS_SPACE_NAME='_rom'
#BASE_CATEGORY_NAME='/UniversalTables'
#LABEL_PREFIX='__'

ROM_START_ADDR=0x40800000
ADDRESS_SPACE_NAME=None
BASE_CATEGORY_NAME='/UniversalTables'
LABEL_PREFIX=''


###############
# ROM offsets table - stolen from unirom :)
# Used to find the two pointers to the tables
# (this may be hard to find automatically - would have to locate the code)
###############

rom_offsets = {
		0x368cadfe: [0x000032c0, 0x00000000, 18, 32, 60, 'IIci'],
		0x36b7fb6c: [0x000032c8, 0x00000000, 18, 32, 60, 'IIsi'],
		0x4147dd77: [0x000032c0, 0x00000000, 18, 32, 60, 'IIfx'],
		0x4957eb49: [0x000032cc, 0x00000000, 18, 32, 60, 'IIvx'],
		0x350eacf0: [0x000032cc, 0x00000000, 18, 32, 60, 'LC'],
		0x35c28f5f: [0x000032b4, 0x00000000, 18, 32, 60, 'LC II'],
		0xecd99dc0: [0x0000322c, 0x00000000, 18, 32, 60, 'Color Classic'],
		0xecfa989b: [0x00003200, 0x000d1540, 18, 32, 60, 'PowerBook Duo 210/230/250'],
		0xec904829: [0x00003220, 0x000d2780, 18, 32, 60, 'LC III'],
		0xecbbc41c: [0x00003220, 0x000d2780, 18, 32, 60, 'LC III'],
		0xede66cbd: [0x00003224, 0x000d1e70, 18, 32, 60, 'LC 520/550 and friends'],
		0xfda22562: [0x0000325c, 0x000a79c0, 18, 32, 60, 'PowerBook 150'],
		0xeaf1678d: [0x00003230, 0x000d0670, 18, 32, 60, 'Macintosh TV / LC 550'],
		0x420dbff3: [0x000031c8, 0x00000000, 18, 32, 60, 'Quadra 700/900, PowerBook 140/170'],
		0xe33b2724: [0x00003218, 0x00000000, 18, 32, 60, 'PowerBook 160/165/165c/180/180c'],
		0xf1a6f343: [0x00003230, 0x000d2800, 18, 32, 60, 'Quadra 800 and friends (earlier)'],
		0xf1acad13: [0x00003230, 0x000d2800, 18, 32, 60, 'Quadra 800 and friends (later)'],
		0x0024d346: [0x0000325c, 0x000a79c0, 18, 32, 68, 'PowerBook Duo 270'],
		0x015621d7: [0x0000325c, 0x000a79c0, 18, 32, 68, 'PowerBook Duo 280'],
		0xff7439ee: [0x0000325c, 0x000a79c0, 18, 32, 68, 'LC 475/575/580/Quadra 605'],
		0xb6909089: [0x0000325c, 0x000a79c0, 18, 32, 68, 'PowerBook 520/540/550'],
		0x06684214: [0x00003260, 0x000a79c0, 18, 32, 68, 'LC 630/Performa 630/Quadra 630'],
		0x064dc91d: [0x00003260, 0x000a79c0, 18, 32, 68, 'LC 580 / Performa 580/588 / Pioneer MPC-LX100'],
		0x5bf10fd1: [0x00013b8c, 0x00013b20, 18, 48, 84, 'Quadra 660AV'],
		0x87d3c814: [0x00013a76, 0x00013ae2, 18, 48, 84, 'Quadra 840AV'],
		0x9feb69b3: [0x000148a0, 0x000148f8, 18, 48, 84, 'PowerMac 6100/7100/8100'],
		0x9a5dc01f: [0x00014e60, 0x00000000, 18, 48, 84, 'STP PowerPC 601 Upgrade Card'],
		0x63abfd3f: [0x000203e0, 0x0002046c, 18, 48, 88, 'PowerMac 5200/5300/6200/6300'],
		0x4d27039c: [0x0003eb50, 0x0003eb6c, 18, 48, 88, 'PowerBook 190'],
		0x83c54f75: [0x0003eb50, 0x0003eb6c, 18, 48, 88, 'PowerBook 520 PPC upgrade'],
		0x83a21950: [0x0003f080, 0x0003f0a4, 18, 48, 88, 'PowerBook 1400'],
		0x852cfbdf: [0x0003ea70, 0x0003ea8c, 18, 48, 88, 'PowerBook 5300'],
		0x2bef21b7: [0x00013b20, 0x00013b28, 18, 48, 88, 'Pippin v1.0'],
		0x575be6bb: [0x00012b30, 0x00012b58, 18, 48, 88, 'Motorola StarMax 3000/4000/5500, Umax C500/600'],
		0x960e4be9: [0x00018840, 0x00018858, 18, 48, 88, 'PowerMac 7300/7600/8600/9600'],
		0x276ec1f1: [0x00013b50, 0x00013b5c, 18, 48, 88, 'PowerBook 2400/3400'],
		0x79d68d63: [0x00012d00, 0x00012d08, 18, 48, 88, 'PowerMac G3 "Beige"'],
		0x78f57389: [0x00012d10, 0x00000000, 18, 48, 88, 'PowerMac G3 "Beige"'],
		0xb46ffb63: [0x00014390, 0x00014398, 18, 48, 88, 'PowerBook G3 "WallStreet"']
}

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

###############
# Creation of datatypes
###############

# BoxInfo field - machine name (stolen from Unirom)
boxnames = [
	"II", "IIx", "IIcx", "SE/30", "Portable", "IIci", "Four Square", "IIfx", "Aurora CX16", "Aurora SE25", "Aurora SE16", "Classic", "IIsi", "LC", "Quadra 900", "PowerBook 170",
	"Quadra 700", "Classic II", "PowerBook 100", "PowerBook 140", "Quadra 950", "LC III", "Sun MAE or Carnation 33", "PowerBook Duo 210", "Centris 650", "Columbia", "PowerBook Duo 230", "PowerBook 180", "PowerBook 160", "Quadra 800", "Quadra 650", "LC II",
	"PowerBook Duo 250", "DBLite 20", "Vail 16", "PowerMac 5200 (was Carnation 25)", "PowerMac 6200 (was Carnation 16)", "Cyclone 33", "Brazil 16L", "IIvx", "Brazil 16F", "Brazil 32F", "Brazil C", "Color Classic", "PowerBook 180c", "Wombat 40", "Centris 610", "Quadra 610",
	"PowerBook 145", "Brazil 32cF", "LC 520", "Unused", "Wombat 20", "Wombat 40F", "Centris 660AV", "88100 or Quadra 700 w/RISC Card", "LC III+", "WLCD33", "PowerMac 8100", "PDM 80F", "PDM 100F", "PowerMac 7500", "PowerMac 7300", "PowerMac 7600/8600/9600",
	"LC 930", "Hokusai", "PowerBook 5x0", "Pippin", "PDM Evt1", "PowerMac 6100", "Yeager FSTN", "PowerBook Duo 270c", "Quadra 840AV", "Tempest 33", "LC 550", "Color Classic", "Centris 650 w/RISC Card", "Color Classic II", "PowerBook 165", "PowerBook 190",
	"LC475 20 MHz", "Optimus 20", "Mac TV", "LC 475", "LC 475 33 MHz", "Optimus 25", "LC 575", "Quadra 605 20 MHz", "Quadra 605", "Quadra 605 33 MHz", "Malcolm 25", "Malcolm 33", "Quadra 630/LC 630", "Tell", "PDM 66WLCD", "PDM 80WLCD",
	"PowerBook Duo 280", "PowerBook Duo 280c", "Quadra 900 w/RISC Card", "Quadra 950 w/RISC Card", "Centris 610 w/RISC Card", "Quadra 800 w/RISC Card", "Quadra 610 w/RISC Card", "Quadra 650 w/RISC Card", "Tempest w/RISC Card", "PDM 50L", "PowerMac 7100", "PDM 80L", "Blackbird BFD", "PowerBook 150", "Quadra 700 w/STP", "Quadra 900 w/STP",
	"Quadra 950 w/STP", "Centris 610 w/STP", "Centris 650 w/STP", "Quadra 610 w/STP", "Quadra 650 w/STP", "Quadra 800 w/STP", "PowerBook Duo 2300", "AJ 80", "PowerBook 5x0 PowerPC upgrade", "Malcolm BB80", "PowerBook 5300", "M2 80", "MAE on HP/UX", "MAE on AIX", "MAE on AUX", "Extended"
]
array_to_enum(boxnames, "boxInfo", 1, subcategory='MachineInfo_fields')

# memDecoderType field - which kind of memory decoder (stolen from Unirom)
decoders = [
	"Unknown", "PALs", "BBU", "Normandy", "Mac II Glue", "MDU", "FMC", "V8/Eagle/Spice", "Orwell", "Jaws", "MSC", "Sonora/Ardbeg/Tinker Bell", "Niagra", "YMCA or djMEMC/MEMCjr/F108",
	"djMEMC/MEMCjr/F108", "HMC", "Pratt", "Hammerhead", "Tinker Bell", "19", "20", "21", "22", "23", "Grackle"
]
array_to_enum(decoders, "memDecoderType", 1, subcategory='MachineInfo_fields')

# Hardware config flags
hwCfgFlagsStruct = parseC("""struct hwCfgFlags {
	bool hasSCSI:1;
    bool hasNewClock:1;
    bool hasXPRam:1;
    bool hasFPU:1;
    bool hasMMU:1;
    bool hasADB:1;
    bool isRunningA_UX:1;
    bool hasPowerManager:1;
};""", subcategory='MachineInfo_fields')

# Flags for whether base addresses defined in memory decoder table
# are actually valid for this specific machine
baseAddrValidFlags = parseC("""struct baseAddrValidFlags {
	bool Unused31Exists:1;		// 0x80000000
	bool NewAgeExists:1;		// 0x40000000
	bool PatchROMAddrExists:1;	// 0x20000000
	bool ROMPhysAddrExists:1;	// 0x10000000
	bool PSC_DMAExists:1;		// 0x8000000
	bool DAFB_or_CivicExists:1;	// 0x4000000
	bool SCSI96_2_extExists:1;	// 0x2000000
	bool SCSI96_1_intExists:1;	// 0x1000000
	bool SONICExists:1;			// 0x800000
	bool JAWSExists:1;			// 0x400000
	bool OrwellExists:1;		// 0x200000
	bool RPUExists:1;			// 0x100000
	bool FMCExists:1;			// 0x80000
	bool OSSExists:1;			// 0x40000
	bool SCCIOPExists:1;		// 0x20000
	bool SWIMIOPExists:1;		// 0x10000
	bool SCSIDMAExists:1;		// 0x8000
	bool VDACExists:1;			// 0x4000
	bool RBVExists:1;			// 0x2000
	bool ASCExists:1;			// 0x1000
	bool VIA2Exists:1;			// 0x800
	bool SCSIHskExists:1;		// 0x400
	bool SCSIDackExists:1;		// 0x200
	bool SCSIExists:1;			// 0x100
	bool SoundExists:1;			// 0x80
	bool PWMExists:1;			// 0x40
	bool IWM_SWIMExists:1;		// 0x20
	bool SCCWriteExists:1;		// 0x10
	bool SCCReadExists:1;		// 0x8
	bool VIA1Exists:1;			// 0x4
	bool diagROMExists:1;		// 0x2
	bool ROMExists:1;			// 0x1
};""", subcategory='MachineInfo_fields')

# Decode multi-bit type for EgretFW
egretFwFlags = parseC("""typedef enum EgretFWFlags {
    None=0,
    Egret8=1,
    Caboose=2,
    CUDA=3,
	FWSpare4=4,
    FWSpare5=5,
    FWSpare6=6,
    FWSpare7=7
} EgretFWFlags;""", subcategory='MachineInfo_fields')

# Decode multi-bit type for Clock
clockFlags = parseC("""typedef enum ClockFlags {
    RTC=0,
    PwrMgr=1,
    Egret=2,
    NoPRAM=3,
    Spare4=4,
    Spare5=5,
    Spare6=6,
    Sprae7=7
} ClockFlags;""", subcategory='MachineInfo_fields')

# Decode multi-bit type for KeySw
keySwFlags = parseC("""typedef enum KeySWFlags {
    None=0,
    Caboose=1,
    Spare2=2,
    Spare3=3
} KeySWFlags;""", subcategory='MachineInfo_fields')

# Decode multi-bit type for ADB
adbEnum = parseC("""typedef enum ADBFlags {
    GITransciever=0,
    PwrMgr=1,
    Iop=2,
    Egret=3,
    Spare4=4,
    Spare5=5,
    Spare6=6,
    Spare7=7
} ADBFlags;""", subcategory='MachineInfo_fields')

# Decode multi-bit type for Sound
# Separate because I have a sneaking suspicion that
# something will just pass around this byte
soundFlags = parseC("""struct SoundFlags {
    bool SoundLineLevel:1;
    bool HasDFAC2:1;
    bool PlayAndRecord:1;
    bool StereoMixing:1;
    bool StereoOut:1;
    bool StereoIn:1;
    bool SixteenBit:1;
    bool HasSoundIn:1;
};""", subcategory='MachineInfo_fields')

# Decode extFeatureFlags (using enums and structs above)
extFeatureFlags = parseC("""struct extFeatureFlags {
    bool hasNewMemMgr:1;
    bool SoftVBL:1;
    bool hasHardPowerOff:1;
    bool SupportsROMDisk:1;
    bool SupportsBtnInt:1;
    enum EgretFWFlags egretFWMask:3;
    bool DJMemCChipBit:1;
    bool SonoraExistsbit:1;
    bool NiagraExistsBit:1;
    bool mscChipBit:1;
    enum KeySWFlags KeySW:2;
    bool PMgrNewIntf:1;
    bool supportsIdle:1;
    struct SoundFlags soundByte;
    bool V8Chip:1;
    enum ClockFlags Clock:3;
    enum ADBFlags ADB:3;
    bool PGCInstalled:1;
};""", subcategory='MachineInfo_fields')

# AddressDecoderInfo "private" fields - negative offset to pointer
# this was 0x24 in size (according to UniversalEqu.a) -
# but I noticed GETVIAINPUTS was being passed the pointer minus 0x14.
# and there are only zeros above this point...
addrDecoderInfoPrivate = parseC("""struct addrDecoderInfo_private {
	// "private" vars that exist at negative offset to pointer, 0x14 in size.
    struct baseAddrValidFlags defaultBases;
    struct extFeatureFlags defaultExtFeatures;
    byte avoidVIA1A;
    byte avoidVIA1B;
    byte avoidVIA2A;
    byte avoidVIA2B;
    long checkForProc;
    byte addrMap;
    byte decoderInfoVers; // 0 for all these
    byte filler[2];
};""", subcategory='AddrDecoder')

# AddressDecoderInfo public fields - positive offset from pointer
addrDecoderInfoPublic = parseC("""struct addrDecoderInfo_public {
	// "public" vars, pointer is to here
	pointer ROM;
	pointer diagROM;
	pointer VIA1;
	pointer SCCRead;
	pointer SCCWrite;
	pointer IWM_SWIM;
	pointer PWM;
	pointer Sound;
	pointer SCSI;
	pointer SCSIDack;
	pointer SCSIHsk;
	pointer VIA2;
	pointer ASC;
	pointer RBV;
	pointer VDAC;
	pointer SCSIDMA;
	pointer SWIMIOP;
	pointer SCCIOP;
	pointer OSS;
	pointer FMC;
	pointer RPU;
	pointer Orwell;
	pointer JAWS;
	pointer SONIC;
	pointer SCSI96_1_int;
	pointer SCSI96_2_ext;
	pointer DAFB_or_Civic;
	pointer PSC_DMA;
	pointer ROMPhysAddr;
	pointer PatchROMAddr;
	pointer NewAge;
	pointer Unused31;
};""", subcategory='AddrDecoder')

# struct to glue the above two together
addrDecoderInfo = parseC("""struct addrDecoderInfo {
	struct addrDecoderInfo_private private;
	struct addrDecoderInfo_public public;
	// there are some more vars in later ROMs...
};""", subcategory='AddrDecoder')

# create "shifted" version of the pointer
# with as base address points to start of addrDecoderInfo_public
# inside addrDecoderInfo, not start of addrDecoderInfo
private_fields_length = addrDecoderInfoPrivate.getLength()
createShiftedPointer(addrDecoderInfo, "addrDecoderInfo_shifted", private_fields_length)

# Decode multi-bit type for designCenter
designCenter = parseC("""typedef enum designCenter {
    highVolume=0,
    portables=1,
    highPerfCisc=2,
    highPerfRisc=3
} designCenter;""", subcategory='CPUID')

# cpuid flags
cpuIDValue = parseC("""struct cpuIDValue {
    enum designCenter designCenter:4;
    bool id_elsewhere:1;
    word cpuid_value:11;
};""", subcategory='CPUID', packing=2)

# cpuid register definition including signature
# no field like that in ROM but useful 
# as a data type for decompilation
cpuid = parseC("""struct cpuid {
	word cpuIDSig; // should be $A55A
	struct cpuIDValue cpuIDValue;
};""", subcategory='CPUID')

# nubus
nuBusSlot = parseC("""struct nuBusSlot {
    bool unused:1;
    bool dockingSlot:1;
    bool slotReserved:1;
    bool directSlot:1;
    bool slotDisabled:1;
    bool hasConnector:1;
    bool canInterrupt:1;
    bool hasPRAM:1;
};""", subcategory='Nubus')

nuBusInfo = parseC("""struct nuBusInfo {
	struct nuBusSlot Slot0;
	struct nuBusSlot Slot1;
	struct nuBusSlot Slot2;
	struct nuBusSlot Slot3;
	struct nuBusSlot Slot4;
	struct nuBusSlot Slot5;
	struct nuBusSlot Slot6;
	struct nuBusSlot Slot7;
	struct nuBusSlot Slot8;
	struct nuBusSlot Slot9;
	struct nuBusSlot SlotA;
	struct nuBusSlot SlotB;
	struct nuBusSlot SlotC;
	struct nuBusSlot SlotD;
	struct nuBusSlot SlotE;
	struct nuBusSlot SlotF;
};""", subcategory='Nubus')

# probably only valid for machines with 18, 32, 60 in table above.
# Need to pull apart some other ROMs to figure out what's going on.
machineInfo = parseC("""struct machineInfo {
    addrDecoderInfo_shifted addrDecoderInfo;
    ulong ramInfo; // not relative to this address, relative to start of struct
    ulong videoInfo; // not relative to this address, relative to start of struct
    nuBusInfo *nuBusInfo;
    hwCfgFlags hwCfgFlags;
    byte unusedBits;
    boxInfo productKindBoxInfo;
    memDecoderType decoderKind;
    word rom85flags;
    byte romRsrcConfig;
    byte ProductInfoVersion; // potentially this tells us field formats
    baseAddrValidFlags baseAddressValidFlags;
    extFeatureFlags extFeatureFlags;
    ulong viaIDMask;
    ulong viaIDMatch;
    ulong extFeatureFlags2;
    ulong extFeatureFlags3;
    int VIA1InitOffset;
    int VIA2InitOffset;
    ulong VIA1InitInfo;
    struct cpuIDFlags MachineCPUID;
	word unusedWord;
};""")

# which pointers from MachineInfo are relative?
machineInfoRelativePointers = [
	"addrDecoderInfo",
	"ramInfo",
	"videoInfo",
	"nuBusInfo"
	# also the VIA?
]

def createStructWithArray(dt_name, count, name, componentName, subcategory=None):
	# Create a struct consisting only of a single array
	# made up of a specified data type and length.
	# Used to create struct for table of MachineInfo pointers
	dt = getDataTypes(dt_name)
	if len(dt) == 0: raise ValueError("data type %s not found" % dt_name)
	if len(dt) != 1: raise ValueError("data type %s has more than one definition" % dt_name)
	s = StructureDataType(subcategory_path(subcategory), name, 0)
	a = ArrayDataType(dt[0], count, 0)
	s.add(a, -1, componentName, None)
	return data_type_manager.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

###############
# Types for function returns
###############

# TODO: put these in a different script for function returns?
# TODO: along with code to find that function and set params/return type

cpuid = parseC("""struct GetCPUIDReg_ret {
	struct cpuid cpuid;
	bool found;
};""", subcategory='func_returns', packing=1)

GetHardwareInfo_ret = parseC("""struct GetHardwareInfo_ret {
	addrDecoderInfo_shifted addrDecoderInfo;
	struct machineInfo *ProductInfo;
	struct baseAddrValidFlags baseAddrValidFlags;
	struct extFeatureFlags extFeaturesFlags;
	byte unused;
	struct hwCfgFlags hwCfgFlags;
	boxInfo boxInfo;
	memDecoderType memDecoderType;
};""", subcategory='func_returns', packing=1)

GetHardwareInfo_D2w = parseC("""struct GetHardwareInfo_D2w {
	boxInfo boxInfo;
	memDecoderType memDecoderType;
};""", subcategory='func_returns', packing=1)


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
	if type(ptr_type) is ghidra.program.database.data.PointerDB:
		return resolveBaseType(ptr_type.getDataType())
	if type(ptr_type) is ghidra.program.database.data.TypedefDB:
		return resolveBaseType(ptr_type.getDataType())
	return ptr_type

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
			elif type(dt) is ghidra.program.database.data.StructureDB:
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

###############
# Analysis functions
###############

def decode_table(table_pos, table_num):
	tableStart = romAddr(table_pos)
	print("Decoding table %i at %s" % (table_num, tableStart))
	
	# label tables
	createLabel(tableStart, LABEL_PREFIX + "Universal_Table_%i" % table_num, True)
	createLabel(tableStart.add(-4), LABEL_PREFIX + "Universal_Table_%i_MinusFour" % table_num, True)

	# keep count of how many machines
	machine_entries = 0
	
	while True:
		table_entry_addr = romAddr(table_pos)
		entry = read_uLong(table_entry_addr)
		
		print("Reading entry at %s : 0x%x" % (table_entry_addr, entry))
		if entry == 0: # last entry in table is NULL
			setEOLComment(table_entry_addr, "end of list")
			break

		machine_entries += 1
		info_ptr = table_entry_addr.add(entry) # MachineInfo struct is this many bytes away relative to this address
		m = structWithRelativePointers(info_ptr, machineInfo, machineInfoRelativePointers) # put the struct on it

		labelName = cleanup_identifier(LABEL_PREFIX + "Machine_%s_%s" % (m.productKindBoxInfo, m.decoderKind))
		print("Labelling machine %s at %s" % (labelName, info_ptr))
		createLabel(info_ptr, labelName , True)

		# hey look what I can do!
		#print(m.addrDecoderInfo.private.defaultBases.IWM_SWIMExists)
		#print(m.nuBusInfo.SlotA)

		# save unique combinations of absolute address for AddressInfo
		# and key against decoders table
		# although theoretically there could be more than one DecoderInfo for a given
		# decoder, it seems there isn't
		addr_decoder_offset = read_int(romAddr(table_pos + entry))
		addr_decoder_ptr = table_pos + entry + addr_decoder_offset
		#addressDecoderInfoTables.add((decoder(decoder_info), addr_decoder_ptr))
		add_managed_table(addrDecoderInfo, romAddr(addr_decoder_ptr - addrDecoderInfoPrivate.getLength()), m.decoderKind)
		# TODO: get data type, address, name? from struct xref?

		# go to next table entry - increment by 4 bytes
		table_pos += 4
	
	# create a struct at the table itself now that we know how many entries it has
	print("got %i machines" % machine_entries)
	# TODO: does prel31 get used by decompiler, or should this be machineInfo*
	# with memory X-ref?
	tableDT = createStructWithArray('prel31', machine_entries, "MachineTable%i" % table_num, "machines", subcategory='MachineTable')
	applyDataType(tableStart, tableDT)
	
	# code uses a pointer to 4 bytes before, then does += 4 at start
	createShiftedPointer(tableDT, "MachineTable%i_Minus4" % table_num, -4) 
	# todo: apply this shifted pointer to where it's used
	# but decompiler won't split out variable coming from argument even when overwritten...


###############
# The main part
###############

checksum_ptr = romAddr(0x0)
checksum = read_uLong(checksum_ptr) # read checksum from ROM
if checksum not in rom_offsets:
	print("Unknown ROM - Unable to find checksum %x in rom_offsets table, exiting" % checksum)
	exit(1)

table_1, table_2, box_offset, via_offset, machine_offset, machine_name = rom_offsets[checksum]
print("Detected ROM as %s" % machine_name)
setEOLComment(checksum_ptr, machine_name) # set a comment at the top of ROM with the detected machine name

addressDecoderInfoTables = set() # create a set for unique address decoders seen

# decode both tables as defined in rom_offsets
decode_table(table_1, 1)
decode_table(table_2, 2)

# label and annotate tables
label_managed_tables()