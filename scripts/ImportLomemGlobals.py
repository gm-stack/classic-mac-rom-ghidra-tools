# Import low memory globals file lomem_globals.txt
#@author gm-stack
#@category MacRomHacking

from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.data import ArrayDataType
import string

functionManager = currentProgram.getFunctionManager()

f = askFile("Select low memory globals file", "Import")

for line in file(f.absolutePath):
    pieces = line.split(None,3)

    name = 'LoMem_'+pieces[0]
    address = toAddr("0x" + pieces[1])
    datatype = pieces[2]
    comment = pieces[3].strip() if len(pieces) >= 4 else None # not all have a comment

    print("adding %s %s %s %s" % (name, address, datatype, comment))
    
    if name != 'LoMem_[????]': # some named [????] - don't label these
        createLabel(address, name, True)

    if getDataAt(address): # remove potentially bogus automatic data references
        removeDataAt(address)

    if datatype in('byte', 'word', 'long'):
        datatype = getDataTypes(datatype)[0]
        createData(address, datatype)
    elif datatype == "-": # label only
        pass
    else: # number of bytes, though maybe not a byte array. Handle that later.
        try:
            dataLength = int(datatype)
            byte = getDataTypes("byte")[0]
            datatype = ArrayDataType(byte, dataLength, byte.getLength())
            createData(address, datatype)
        except ValueError:
            pass # something else entirely, do nothing
    
    if comment:
        setEOLComment(address, comment)

