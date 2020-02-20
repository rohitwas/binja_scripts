'''

Finds functions that end with a 
"retn 0x8" instruction


'''


retns = []
funcs = bv.functions
for each_func in funcs:
    for each_ins in each_func.instructions:
        if "retn" in str(each_ins[0][0]):
            if len(each_ins[0]) >2:
                if "0x8" in str(each_ins[0][2]):
                    retns.append({str(each_func.symbol.full_name) : hex(each_func.start) })



'''
example ouput

{'Js::BigInt::FInitFromRglu(uint32_t*, int32_t)': '0x1033f227L'}, 
{'Js::SSE2::JavascriptMath::Decrement_Full(void*, class Js::ScriptContext*)': '0x1033fa00L'},
{'sub_1033fb72': '0x1033fb72L'}, 
{'Js::SSE2::JavascriptMath::Negate_Full(void*, class Js::ScriptContext*)': '0x10340310L'}, 

'''
