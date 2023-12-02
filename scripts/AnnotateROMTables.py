# Find the machine table in an old world ROM image and annotate with comments, labels, references and data types
# @author gm-stack - initial values for rom_offsets and some names stolen from rb6502's unirom https://github.com/rb6502/unirom
# @category MacRomHacking
#

from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import ArrayDataType, EnumDataType, PointerTypedef
from ghidra.program.model.symbol.RefType import DATA as RefType_Data
from ghidra.app.cmd.data import CreateArrayCmd
from ghidra.program.model.data import DataTypeConflictHandler, DataUtilities
from ghidra.app.util.cparser.C import CParser

import string

ROM_START_ADDR=0x0
MEMORY_MAP_NAME='_rom'

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
def boxname(num):
	if num >= 128: return "unknown (%i)" % num
	return boxnames[num]

decoders = [
	"Unknown", "PALs", "BBU", "Normandy", "Mac II Glue", "MDU", "FMC", "V8/Eagle/Spice", "Orwell", "Jaws", "MSC", "Sonora/Ardbeg/Tinker Bell", "Niagra", "YMCA or djMEMC/MEMCjr/F108",
	"djMEMC/MEMCjr/F108", "HMC", "Pratt", "Hammerhead", "Tinker Bell", "19", "20", "21", "22", "23", "Grackle"
]
def decoder(num):
	if num >= 25: return "unknown (%i)" % num
	return decoders[num]

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

data_type_manager = currentProgram.getDataTypeManager()

def parseC(struct_txt):
	parser = CParser(data_type_manager)
	parsed_datatype = parser.parse(struct_txt)
	return data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.REPLACE_HANDLER)

def cleanup_identifier(dirty_name):
	if dirty_name[0].isnumeric():
		dirty_name = '_' + dirty_name
	chars_to_replace = "/ ()"
	for c in chars_to_replace:
		dirty_name = dirty_name.replace(c, "_")
	dirty_name = dirty_name.replace("+","plus")
	return dirty_name

def array_to_enum(data, name, size):
	already_included=set()
	enum = EnumDataType(name, size)
	for count, value in enumerate(data):
		clean_identifier = cleanup_identifier(value)
		while clean_identifier in already_included:
			clean_identifier += '_'
		already_included.add(clean_identifier)
		enum.add(clean_identifier, count)
	data_type_manager.addDataType(enum, DataTypeConflictHandler.REPLACE_HANDLER)

array_to_enum(boxnames, "boxInfo", 1)
array_to_enum(decoders, "memDecoderType", 1)


hwCfgFlagsStruct = parseC("""struct hwCfgFlags {
	bool hasSCSI:1;
    bool hasNewClock:1;
    bool hasXPRam:1;
    bool hasFPU:1;
    bool hasMMU:1;
    bool hasADB:1;
    bool isRunningA_UX:1;
    bool hasPowerManager:1;
};""")

baseAddrFlags = parseC("""struct baseAddrFlags {
	bool Unused31Exists:1;
	bool NewAgeExists:1;
	bool PatchROMAddrExists:1;
	bool ROMPhysAddrExists:1;
	bool PSC_DMAExists:1;
	bool DAFB_or_CivicExists:1;
	bool SCSI96_2_extExists:1;
	bool SCSI96_1_intExists:1;
	bool SONICExists:1;
	bool JAWSExists:1;
	bool OrwellExists:1;
	bool RPUExists:1;
	bool FMCExists:1;
	bool OSSExists:1;
	bool SCCIOPExists:1;
	bool SWIMIOPExists:1;
	bool SCSIDMAExists:1;
	bool VDACExists:1;
	bool RBVExists:1;
	bool ASCExists:1;
	bool VIA2Exists:1;
	bool SCSIHskExists:1;
	bool SCSIDackExists:1;
	bool SCSIExists:1;
	bool SoundExists:1;
	bool PWMExists:1;
	bool IWM_SWIMExists:1;
	bool SCCWriteExists:1;
	bool SCCReadExists:1;
	bool VIA1Exists:1;
	bool diagROMExists:1;
	bool ROMExists:1;
};""")

# probably only valid for machines with 18, 32, 60 in table above.
# Need to pull apart some other ROMs to figure out what's going on.

machineInfo = parseC("""struct machineInfo {
    prel31 addrDecoderInfo;
    prel31 RamInfo;
    prel31 VideoInfo;
    prel31 NuBusInfo;
    hwCfgFlags hwCfgFlags;
    byte unusedBits;
    boxInfo productKindBoxInfo;
    memDecoderType decoderKind;
    word rom85flags;
    byte romRsrcConfig;
    byte ProductInfoVersion; // potentially this tells us field formats
    baseAddrFlags baseAddressFlags0_31;
    ulong extFeatureFlags;
    ulong via1;
    ulong via2;
    ulong extFeatureFlags2;
    ulong extFeatureFlags3;
    int VIA1InitOffset;
    int VIA2InitOffset;
    prel31 VIA1InitInfo;
    ulong MachineCPUID;
};""")

addrDecoderInfo = parseC("""struct addrDecoderInfo {
	// "private" vars, 0x24 in size. Need to make "shifted" type in this script.
    long unknown1;
    long unknown2;
    long unknown3;
    long unknown4;
    long defaultBases;
    long defaultExtFeatures;
    byte avoidVIA1A;
    byte avoidVIA1B;
    byte avoidVIA2A;
    byte avoidVIA2B;
    long checkForProc;
    byte addrMap;
    byte decoderInfoVers;
    byte filler[2];

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
	// pointer Singer; // too long given minimum spacing in ROM. I believe this is not in version 0.
	// pointer DSP;
	// pointer MACE;
	// pointer MUNI;
	// pointer AMIC_DMA;
	// pointer Pratt;
	// pointer SWIM3;
	// pointer AWACS;
	// pointer Civic;
	// pointer Sebastian;
	// pointer BART;
	// pointer Grand_Central;
};""")

def createShiftedPointer(data_type, name, shift):
	shifted = PointerTypedef(name, data_type, -1, data_type_manager, shift)
	data_type_manager.addDataType(shifted, DataTypeConflictHandler.REPLACE_HANDLER)
	return shifted

createShiftedPointer(addrDecoderInfo, "addrDecoderInfo_public", 0x24)


memory = currentProgram.getMemory()

def readDT(address,data_type,readfunc,sizemask):
	data = readfunc(address)
	if sizemask: data = data & sizemask
	return data

read_uLong = lambda a: readDT(a, 'long', memory.getInt, 0xFFFFFFFF)
read_long = lambda a: readDT(a, 'long', memory.getInt, None)
read_uWord = lambda a: readDT(a, 'word', memory.getShort, 0xFFFF)
read_uByte = lambda a: readDT(a, 'byte', memory.getByte, 0xFF)

romAddr = lambda a: toAddr('%s%s%x' % (MEMORY_MAP_NAME, ':' if MEMORY_MAP_NAME else '' ,ROM_START_ADDR + a))

checksum_ptr = romAddr(0x0)
checksum = read_uLong(checksum_ptr)
if checksum not in rom_offsets:
	print("Unable to find checksum %x in table, exiting" % checksum)
	exit(1)

table_1, table_2, box_offset, via_offset, machine_offset, machine_name = rom_offsets[checksum]
print("Detected ROM as %s" % machine_name)
setEOLComment(checksum_ptr, machine_name)

forceSetDataType = lambda addr, dtype: DataUtilities.createData(
	currentProgram, addr, dtype, 0, 
	False, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
)

addressDecoderInfoTables = set()

def decode_table(table_pos, table_num):
	tableStart = romAddr(table_pos)
	print("Decoding table %i at %s" % (table_num, tableStart))
	
	createLabel(tableStart, "__Universal_Table_%i" % table_num, True)
	createLabel(tableStart.add(-4), "__Universal_Table_%i_MinusFour" % table_num, True)
	machine_entries = 0
	
	while True:
		table_entry_addr = romAddr(table_pos)
		entry = read_uLong(table_entry_addr)
		
		print("Reading entry at %s : 0x%x" % (table_entry_addr, entry))
		if entry == 0:
			setEOLComment(table_entry_addr, "end of list")
			break

		machine_entries += 1
		info_ptr = table_entry_addr.add(entry)
		forceSetDataType(info_ptr, machineInfo)

		box_ptr = info_ptr.add(box_offset)
		boxInfo = read_uByte(box_ptr)
		decoder_id_ptr = info_ptr.add(box_offset+1)
		decoder_info = read_uByte(decoder_id_ptr)
		labelName = "__Machine_%s_%s" % (boxname(boxInfo).replace(" ","_"),decoder(decoder_info).replace(" ","_"))
		print("Labelling machine %s at %s" % (labelName, info_ptr))
		createLabel(info_ptr, labelName , True)

		# save unique combinations of absolute address decoder mem info and decoder name
		addr_decoder_offset = read_long(info_ptr)
		addr_decoder_ptr = table_pos + entry + addr_decoder_offset
		addressDecoderInfoTables.add((decoder(decoder_info), addr_decoder_ptr))

		# next table entry
		table_pos += 4
	
	# make a nice array of machines, using prel31 datatype to have Ghidra resolve relative pointers
	print("got %i machines" % machine_entries)
	prel31 = getDataTypes('prel31')[0]
	runCommand(CreateArrayCmd(tableStart, machine_entries + 1, prel31, 0))

decode_table(table_1, 1)
decode_table(table_2, 2)

# label and annotate Memory Decoder tables
for decoder_table_name, decoder_table_addr in addressDecoderInfoTables:
	print("labelling %s @ %s:0x%x" % (decoder_table_name, MEMORY_MAP_NAME, decoder_table_addr))
	tableStart = romAddr(decoder_table_addr - 0x24)
	createLabel(tableStart, "__MemCtrl_%s" % cleanup_identifier(decoder_table_name), True)
	forceSetDataType(tableStart, addrDecoderInfo)