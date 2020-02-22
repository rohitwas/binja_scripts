
''' 
For Windwos binaries, find all potential thiscall functions which are misidentified as 'cdecl' 

logic : iterate thru all mlil instructions of type MLIL_SET_VAR and 
if within the first basic block (or so)  there is an ssa_ins.src.value.reg == 'ecx' 
and 
no previous instruction had a ssa_ins.dest.name == 'ecx' 
then this is likely a thiscall

TODO: also look at return statements for evidence of stack cleaning (callee)?
'''


'''
LLIL version

'''
# count = 0
# for funcs in bv.functions:
#     mlil = funcs.llil_instructions
#     ecx_source = 0
#     ecx_dest = 0
#     for mlil_ins in mlil:
#         if mlil_ins.operation == LowLevelILOperation.LLIL_SET_REG or mlil_ins.operation == LowLevelILOperation.LLIL_STORE :
#             #if mlil_ins.src.value.reg == 'ecx':
#             if (len(mlil_ins.src.operands) > 0):
#                 if mlil_ins.src.operands[0] == 'ecx':
#                     if ecx_dest ==1:
#                         ecx_dest =0
#                         break
#                     else:
#                         count+=1
#                         print "Found a thiscall at %s"%(funcs.symbol.full_name)
#                         ecx_dest = 0
#                         break
#                 if mlil_ins.dest == 'ecx':
#                     ecx_dest =1


'''
MLIL version

'''
count = 0
for funcs in bv.functions:
    mlil = funcs.mlil_instructions
    ecx_source = 0
    ecx_dest = 0
    if funcs.calling_convention.name == 'cdecl' :
        for mlil_ins in mlil:
            if mlil_ins.operation == MediumLevelILOperation.MLIL_SET_VAR :
                if mlil_ins.src.value.reg == 'ecx':
                    if ecx_dest ==1:
                        ecx_dest =0
                        break
                    else:
                        count+=1
                        print "Found a thiscall at %s"%(funcs.symbol.full_name)
                        ecx_dest = 0
                        break
                if mlil_ins.dest == 'ecx':
                    ecx_dest =1
print "Found a total of %s functions with thicall misidentified"%(count)

