    bv.parse_type_string("void *")[0] 
is a life saver
example Type.Function() for memset

    Type.function(bv.parse_type_string("void *")[0] , [bv.parse_type_string("void *")[0],bv.parse_type_string("int")[0],bv.parse_type_string("size_t")[0]] , bv.arch.calling_conventions['stdcall'] , False)


Type.function(bv.parse_type_string("void ")[0] , [bv.parse_type_string("void ")[0]] , bv.arch.calling_conventions['thiscall'] , False)


    get_parameter_at_low_level_il_instruction(instr, func_type, i) 
note: the instr parameter is type `size_t` that is it expects the index of the instruction in the llil

example

    current_function.get_parameter_at_low_level_il_instruction(13,a,0)
