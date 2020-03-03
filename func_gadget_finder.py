"""
IE 11 has a protection that , on top of CFG, restricts you to only calling indirect functions 
which have similar type signature as the intended function. This is done because in 'thiscall' convention the callee
is responsible for stack cleanup
Specifically there is a stack pointer save before the actual indirect call and compare after the call which ensures
that you can only call functions with the same number of arguments as intended. 

This particular script attempts to find functions with the following criteria -
a) Funciton's RVA is listed in the CFG table/is a valid indirect call location
b) has 2 arguments , i.e have a retn 0x8 instruction at the end of the function
c) there is a memory write in a memory location which is referenced as a double pointer either directly or indirectly 
   via the 'this' pointer (ecx/rcx)
   essentially any writes of the form  *(*(this+ index) )

note: This script currently doesnt rely on BN's analyzer to recognize CFG table. There is some unreliability which
has been reported as an issue here-
https://github.com/Vector35/binaryninja-api/issues/1542

"""

def func_gadget_find(each_func):
    try:
        i = 0
        while(1):
            memory_uses = each_func.mlil.ssa_form.get_ssa_memory_uses(i)
            if (memory_uses == []) :
                break
            hit = 0
            sink1 = []
            sink2 = []
            sink3 = []
            for each_use in memory_uses:
                if each_use.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    if len(each_use.vars_read) == 0:
                        continue
                    if len(each_use.vars_written) == 0:
                        continue
                    vars_read = each_use.vars_read[0]
                    vars_written = each_use.vars_written[0]
                    read_ins = each_func.mlil.get_ssa_var_definition(each_use.vars_read[0])        
                    
                    if 'ecx' not in str(vars_read.var):
                        if read_ins == None:
                            continue   
                    # If memory is being read from ecx or another register that was previously assigned to ecx
                    if str(read_ins.src) == 'ecx' or 'ecx' in str(vars_read.var):
                        sink1.append(vars_written)
                    for sinks in sink1 :
                        if vars_read == sinks:
                            sink2.append(vars_written)
                    for sinks in sink2:
                        if vars_read == sinks:
                            sink3.append(vars_read)
                
                if each_use.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                    vars_written = each_use.dest.ssa_form.vars_read[0] # note: for MLIL_STORE_SSA vars_written is an empty []
                    for sinks in sink3:
                        if vars_written ==sinks:
                            print "[*] Found a write via @ %s vars_written:%s sinks:%s a double de-reference of this/ecx!\n %s , %s \n"%(each_use, vars_written,sinks, each_func.symbol.full_name, hex(each_func.start))             
                            hit =1
                            break
            if hit == 1:
                break
            i=i+1
    except:
        pass



def parse_data_view(structure, address):
    PE = StructuredDataView(bv, structure, address)
    return PE

def byte_swap(i):
    i =str(i).replace(" ", "")
    temp = int (i,16)
    return struct.unpack("<I", struct.pack(">I", temp))[0]
 

#Check if BN was able to parse CFG headers successfully?
data_keys = bv.data_vars.keys()
data_vals = bv.data_vars.values()
lcte_index = 0
cfg_index=0
for index in range(0,len(data_vals)):
  if "Guard_Control_Flow_Function_Table" in str(data_vals[index]):
    cfg_index = index
  if "Load_Configuration_Directory_Table" in str(data_vals[index]):
    lcte_index = index

if  cfg_index !=0 and lcte_index!=0:
    #print "Found Load Config Dir. Table table at %s"%(hex(data_keys[lcte_index])) # address of the CFG Function Table 
    #print "Found CFG table at %s"%(hex(data_keys[cfg_index])) # address of the CFG Function Table 
    GuardCFFunctionTable_virtualAddress = data_keys[cfg_index]
    lcte_virtualAddress = data_keys[lcte_index]
    lcte = parse_data_view("Load_Configuration_Directory_Table",lcte_virtualAddress)
    GuardCFFunctionTable_size = byte_swap(lcte.guardCFFunctionCount.str)
else:
    lcte = parse_data_view("PE_Data_Directory_Entry",(bv.start + 0x1c8))
    print "blah blah blah" +str(lcte)
    lcte_virtualAddress = byte_swap(lcte.virtualAddress)#RVA
    lcte_size = byte_swap(lcte.size)
    lcte_virtualAddress = lcte_virtualAddress + bv.start
    GuardCFFunctionTable_offset = bv.types["SIZE_T"].width * 4 #16/32
    GuardCFFunctionTable = parse_data_view("PE_Data_Directory_Entry", (lcte_virtualAddress + lcte_size + GuardCFFunctionTable_offset ))    
    GuardCFFunctionTable_virtualAddress = byte_swap(GuardCFFunctionTable.virtualAddress)#RVA
    GuardCFFunctionTable_size = byte_swap(GuardCFFunctionTable.size)


br = BinaryReader(bv)
br.offset = (GuardCFFunctionTable_virtualAddress)

#Find all functions within the CFG Table
CFG_funcs = []
for i in range(0, GuardCFFunctionTable_size):
    CFG_RVA = br.read32le()
    CFG_byte = br.read8()
    #CFG_funcs.append(bv.get_function_at(bv.start + CFG_RVA).symbol.full_name)
    CFG_funcs.append(bv.get_function_at(bv.start + CFG_RVA))

if GuardCFFunctionTable_size == len(CFG_funcs):
    print "[*] Found %s CFG Valid Functions"%(len(CFG_funcs))
else:
    print "[*] Number of functions within the CFG Table dont match Function count within the CFG headers"

retn_func_count = 0
#Filter those functions with "retn 0x8" instructions
for each_func in CFG_funcs:
    retn_ins = 0
    for each_ins in each_func.instructions:
        if "retn" not in str(each_ins[0][0]):
            continue
        if not len(each_ins[0]) >2:
            continue
        if "0x8" not in str(each_ins[0][2]):
            continue
        retn_ins = 1
        break
    if retn_ins ==1:
        retn_func_count+=1
        func_gadget_find(each_func)

print "[*] Found %s functions with the return instruction criteria"%(retn_func_count)