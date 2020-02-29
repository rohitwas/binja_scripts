"""
IE 11 has a protection that , on top of CFG, restricts you to only calling indirect functions 
which have similar type signature as the intended function. This is done because in 'thiscall' convention the callee
is responsible for stack cleanup
Specifically there is a stack pointer save before the actual indirect call and compare after the call which ensures
that you can only call functions with the same number of arguments as intended. 

This particular script attempts to find functions with the following criteria -
a) has 2 arguments , i.e have a retn 0x8 instruction at the end of the function
b) there is a memory write in a memory location which is referenced as a double pointer either directly or indirectly 
   via the 'this' pointer (ecx/rcx)
   essentially any writes of the form  *(*(this+ index) )

note-We currently search across all functions and not just CFG valid functions. 
BN doesnt recognize the CFG Function Table from the PE Header. Needs another script that parses CFG function Table
and only looks at those which can be valid indirect call targets

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


funcs = bv.functions
for each_func in funcs:
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
        func_gadget_find(each_func)
