"""
weirdly, it seems that BN *does* identify CFG table in certain PEs? (example jscript.dll)
This can be seen by retrieving the data vars from a binary view and looking for 
struct Guard_Control_Flow_Function_Table in the values of the data_vars dict

"""
a = bv.data_vars.keys()
b = bv.data_vars.values()
cfg_index=0
for index in range(0,len(b)):
  if "Guard_Control_Flow_Function_Table" in str(b[index]):
    cfg_index = index
if cfg_index !=0:
    print hex(a[cfg_index]) # address of the CFG Function Table
 
