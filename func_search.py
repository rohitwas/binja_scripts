'''

Finds functions that end with a 
"retn 0x8" instruction by searching each instruction within the function boundary

note: This can be done via a simple current_function.stack_adjustment.value == 8 statement
*but* we would miss some odd cases like functions which have alternate paths that do not return and 
the stack_adjustment value is ambiguous/indeterminate.

examples-
< jscript9.dll 11.0.18362.657 March 4th 2020> 
ScriptEngineBase::ReleaseAndRethrowException(@0x1665e0L) 
JsrtExternalObject::SetConfigurable (@0x175d90L)
'''


retns = []
funcs = bv.functions
for each_func in funcs:
    for each_ins in each_func.instructions:
        if "retn" not in str(each_ins[0][0]):
        	continue
        if not len(each_ins[0]) >2:
            continue
        if "0x8" not in str(each_ins[0][2]):
        	continue
        retns.append({str(each_func.symbol.full_name) : hex(each_func.start) })
print retns

'''
example ouput

{'Js::BigInt::FInitFromRglu(uint32_t*, int32_t)': '0x1033f227L'}, 
{'Js::SSE2::JavascriptMath::Decrement_Full(void*, class Js::ScriptContext*)': '0x1033fa00L'},
{'sub_1033fb72': '0x1033fb72L'}, 
{'Js::SSE2::JavascriptMath::Negate_Full(void*, class Js::ScriptContext*)': '0x10340310L'}, 

'''
