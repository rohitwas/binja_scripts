stdcall_count = 0
cdecl_count = 0
fastcall_count = 0
thiscall_count= 0

for i in bv.functions:
    #s = i.type_tokens
    s = i.calling_convention.name
    s2 = "".join([str(elem) for elem in s])
    if "stdcall" in str(s2):
        stdcall_count+=1
    if "cdecl" in str(s2):
        cdecl_count+=1
    if "fastcall" in str(s2):
        fastcall_count+=1       
    if "thiscall" in str(s2):
        thiscall_count+=1

print("Found stdcall: %s\n cdecl: %s\n fastcall: %s\n thiscall: %s\n "%(stdcall_count,cdecl_count,fastcall_count,thiscall_count))


"""
BINJA results on jscript9.dll using [for each in bv.functions].type_token

stdcall_count :1391
cdecl_count: 15
fastcall_count: 439
thiscall_count: 0


BINJA results on jscript9.dll using [for each in bv.functions].calling_convention.name

stdcall_count
1376
cdecl_count
16316
fastcall_count
439
thiscall_count
4153


IDA results on jscript9.dll using idc.GetType()
stdcall: 2723
cdecl: 469
fastcall: 44
thiscall: 5294
 
"""