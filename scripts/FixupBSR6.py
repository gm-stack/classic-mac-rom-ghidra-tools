# Fixup flow for BSR6 function calls where return address is put into A6 and JMP'd to.
# Ghidra doesn't treat the JMP as a call, and doesn't understand the subsequent JMP (a6)
# is not a jump table (the size of the whole addr space)
#@author gm-stack
#@category MacRomHacking

from ghidra.program.model import scalar
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import Instruction, FlowOverride
from ghidra.program.model.lang import OperandType, Register

def fixupBSR6(ip):
    # I was tempted to regex on the result of toString()...
    if not ip.getMnemonicString() == 'lea': return
    if not ip.getNumOperands() == 2: return
    if not ip.getOperandType(1) == OperandType.REGISTER: return
    if not ip.getRegister(1).getName() == 'A6': return
    if not ip.getOperandType(0) == (OperandType.DYNAMIC | OperandType.ADDRESS): return
    objects = ip.getOpObjects(0)
    if not len(objects) == 2: return
    if not type(objects[0]) is ghidra.program.model.scalar.Scalar: return
    if not type(objects[1]) is ghidra.program.model.lang.Register: return
    if not objects[1].getName() == 'PC': return
    
    # if we got to this point, it's definitely 'lea (???,PC),A6', now check the next one is a JMP
    ip2 = getInstructionAfter(ip)

    if not (ip2.getMnemonicString() == 'jmp' and ip2.getNumOperands() == 1):
        print("Found '%s' at %s, but followed by '%s' not 'JMP _label'" % (ip, ip.getMinAddress(), ip2))
        return
    
    if not (ip2.getOperandType(0) == OperandType.ADDRESS | OperandType.CODE):
        if (ip2.getOperandType(0) == OperandType.ADDRESS):
            print("Found '%s' at %s but jump not to code" % (ip2, ip2.getMinAddress()))
            return
        return

    offset = objects[0].getValue()
    
    # instruction that follows 'lea (???,PC),A6' is a 'JMP' to a fixed offset, let's fix it up 
    print("Fixing BSR6 with offset 0x%x at %s" % (offset, ip2.getMinAddress()))

    # attempt to disassemble next instruction so that Ghidra doesn't change it
    # to CALL_RETURN as it's the last code it sees
    next_instruction_start = ip2.getMaxAddress().add(1)
    disassemble(next_instruction_start)
    
    # Set flow override = CALL
    ip2.setFlowOverride(FlowOverride.CALL)

    # now check the destination is a function
    bsr6_dest = ip2.getOpObjects(0)[0]
    bsr6_func = getFunctionAt(bsr6_dest)
    if bsr6_func:
        print("BSR6 already goes to %s" % bsr6_func.getName())
        return
    
    new_func = createFunction(bsr6_dest, None)
    print("pointed bsr6 at function %s" % new_func.getName())
    

def fixupReturnA6(ip):
    if not (ip.getMnemonicString() == 'jmp' and ip.getNumOperands() == 1): return
    if not ip.getOperandType(0) == OperandType.REGISTER | OperandType.INDIRECT: return
    if not ip.getRegister(0).getName() == 'A6': return
    
    ip.setFlowOverride(FlowOverride.RETURN)
    print("Set 'jmp (A6)' at %s to RETURN" % ip.getMinAddress())

ip = getFirstInstruction();
while True:
    fixupBSR6(ip)
    fixupReturnA6(ip)
    
    ip = getInstructionAfter(ip)
    if (ip == None): break