# Fixup flow for BSR5/BSR6/BigBSR5/BigBSR6 function calls where return address is put into A5/A6 and JMP'd to.
# Ghidra doesn't treat the JMP as a call, and doesn't understand the subsequent JMP (a5) / JMP (a6)
# is not a jump table (the size of the whole addr space)
#@author gm-stack
#@category MacRomHacking

from ghidra.program.model import scalar
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import Instruction, FlowOverride
from ghidra.program.model.lang import OperandType, Register

reference_manager = currentProgram.getReferenceManager()

def fixupBigBSR(ip2):
    # if second instruction is also 'lea', this may be a BigBSRx instead
    # some of our work has already been done, first instruction is a PC relative load to Ax
    # TODO: check offset of that jump. Though there is at least one "custom" BSRx that returns somewhere else
    if not ip2.getNumOperands() == 2: return
    if not ip2.getOperandType(0) == OperandType.SCALAR: return
    if not ip2.getOperandType(1) == OperandType.REGISTER: return
    ip2_dest_register = ip2.getRegister(1).getName() # it's not always A0, it sometimes seems to be A2?
    objects = ip2.getOpObjects(0)
    if not len(objects) == 1: return
    if not type(objects[0]) is ghidra.program.model.scalar.Scalar: return
    ip2_op_addr = objects[0]

    ip3 = getInstructionAfter(ip2)
    # now check if it is followed by a jmp, to the value stored by ip2 in whatever register ip2 did
    if not ip3.getMnemonicString() == 'jmp': return
    if not ip3.getNumOperands() == 1: return
    if not ip3.getOperandType(0) == (OperandType.DYNAMIC | OperandType.INDIRECT): return
    objects = ip3.getOpObjects(0)
    if not len(objects) == 4: return
    if not type(objects[0]) is ghidra.program.model.scalar.Scalar: return
    if not type(objects[1]) is ghidra.program.model.lang.Register: return
    if not type(objects[2]) is ghidra.program.model.lang.Register: return
    if not type(objects[3]) is ghidra.program.model.scalar.Scalar: return
    ip3_op_addr = objects[0] # JMP relative to PC
    if not objects[1].getName() == 'PC': return
    if not objects[2].getName() == ip2_dest_register: return    # check it's the same register as preceding instruction
    if not objects[3].getValue() == 0x1: return                 # scale should be 0x1
    
    # well if all that's true, it's probably what we want. let's work out where it points.
    ip2_op_addr = ip2_op_addr.getSignedValue()    
    ip3_op_addr = ip3_op_addr.getUnsignedValue()
    final_dest = ip3_op_addr + ip2_op_addr
    
    addr_space = ip3.getMinAddress().getAddressSpace()
    bsr6_dest = addr_space.getAddressInThisSpaceOnly(final_dest)

    print("Fixing BigBSR(%s) with dest %s at %s" % (register, bsr6_dest, ip3.getMinAddress()))

    # attempt to disassemble next instruction so that Ghidra doesn't change it
    # to CALL_RETURN as it's the last code it sees
    next_instruction_start = ip3.getMaxAddress().add(1)
    disassemble(next_instruction_start)
    
    # Set flow override = CALL
    ip3.setFlowOverride(FlowOverride.CALL)

    # Add memory reference UNCONDITIONAL_CALL to dest
    reference_manager.addMemoryReference(ip3.getMinAddress(), bsr6_dest, FlowType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)

    # now check the destination is a function
    bsr6_func = getFunctionAt(bsr6_dest)
    if bsr6_func:
        print("BigBSR already goes to %s" % bsr6_func.getName())
        return
    
    new_func = createFunction(bsr6_dest, None)
    print("pointed BigBSR at function %s" % new_func.getName())
    

def fixupBSR(ip, register):
    # I was tempted to regex on the result of toString()...
    if not ip.getMnemonicString() == 'lea': return
    if not ip.getNumOperands() == 2: return
    if not ip.getOperandType(1) == OperandType.REGISTER: return
    if not ip.getRegister(1).getName() == register: return
    if not ip.getOperandType(0) == (OperandType.DYNAMIC | OperandType.ADDRESS): return
    objects = ip.getOpObjects(0)
    if not len(objects) == 2: return
    if not type(objects[0]) is ghidra.program.model.scalar.Scalar: return
    if not type(objects[1]) is ghidra.program.model.lang.Register: return
    if not objects[1].getName() == 'PC': return
    
    # if we got to this point, it's definitely 'lea (???,PC),Ax', now check the next one is a JMP
    ip2 = getInstructionAfter(ip)
    second_instr = ip2.getMnemonicString()

    if not (second_instr == 'jmp' and ip2.getNumOperands() == 1):
        if second_instr == 'lea':
            return fixupBigBSR(ip2) # it might be a BigBSRx instead
        print("Found '%s' at %s, but followed by '%s' not 'JMP _label'" % (ip, ip.getMinAddress(), ip2))
        return
    
    if not (ip2.getOperandType(0) == OperandType.ADDRESS | OperandType.CODE):
        if (ip2.getOperandType(0) == OperandType.ADDRESS):
            print("Found '%s' at %s but jump not to code" % (ip2, ip2.getMinAddress()))
            return
        return

    offset = objects[0].getValue()
    
    # instruction that follows 'lea (???,PC),Ax' is a 'JMP' to a fixed offset, let's fix it up 
    print("Fixing BSR(%s) with offset 0x%x at %s" % (register, offset, ip2.getMinAddress()))

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