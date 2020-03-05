from binaryninja import *


def func_gadget_find(each_func,found):
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
                    #If memory is being read from ecx or another register that was previously assigned to ecx
                    if str(read_ins.src) == 'ecx' or 'ecx' in str(vars_read.var):
                        sink1.append(vars_written)
                    for sinks in sink1 :
                        if vars_read == sinks:
                            sink2.append(vars_written)
                    for sinks in sink2:
                        if vars_read == sinks:
                            sink3.append(vars_read)
                
                if each_use.operation == MediumLevelILOperation.MLIL_STORE_SSA:
                    # note: for MLIL_STORE_SSA vars_written is an empty []
                    vars_written = each_use.dest.ssa_form.vars_read[0] 
                    for sinks in sink3:
                        if vars_written ==sinks:
                            print "[*] Found a write via @ %s vars_written:%s sinks:%s a \
                            double de-reference of this/ecx!\n %s , %s \n"%(each_use, 
                                vars_written,sinks, each_func.symbol.full_name, hex(each_func.start))
                            hit =1
                            found[0] =1          
                            break
            if hit == 1:
                break
            i=i+1
    except:
        pass

def func_search(each_func):    
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
        return retn_ins

def parse_data_view(structure, address,bv):
    PE = StructuredDataView(bv, structure, address)
    return PE

def byte_swap(i):
    i =str(i).replace(" ", "")
    temp = int (i,16)
    return struct.unpack("<I", struct.pack(">I", temp))[0]



def scan_binary(bin):
    print "Analyzing %s"%(bin)
    bv = BinaryViewType["PE"].open(bin)
    bv.update_analysis_and_wait()
    br = BinaryReader(bv)

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

    if cfg_index !=0 and lcte_index!=0:
        GuardCFFunctionTable_virtualAddress = data_keys[cfg_index]
        lcte_virtualAddress = data_keys[lcte_index]
        lcte = parse_data_view("Load_Configuration_Directory_Table", lcte_virtualAddress, bv)
        br.offset = lcte.guardCFFunctionCount.address
        if "uint64_t" in str(lcte.guardCFFunctionCount.type):
            GuardCFFunctionTable_size = br.read64le()
        elif "uint32_t" in str(lcte.guardCFFunctionCount.type):
            GuardCFFunctionTable_size = br.read32le()
    else:
        lcte = parse_data_view("PE_Data_Directory_Entry",(bv.start + 0x1c8) , bv)#hardcoded for now
        lcte_virtualAddress = byte_swap(lcte.virtualAddress)#RVA
        lcte_size = byte_swap(lcte.size)
        lcte_virtualAddress = lcte_virtualAddress + bv.start
        GuardCFFunctionTable_offset = bv.types["SIZE_T"].width * 4 #16/32
        GuardCFFunctionTable = parse_data_view("PE_Data_Directory_Entry", (lcte_virtualAddress + lcte_size + 
            GuardCFFunctionTable_offset ), bv)    
        GuardCFFunctionTable_virtualAddress = byte_swap(GuardCFFunctionTable.virtualAddress)#RVA
        GuardCFFunctionTable_size = byte_swap(GuardCFFunctionTable.size)

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
    #for each_func in bv.functions:
        #if func_search(each_func) == 1:        
        if each_func.stack_adjustment.value == 8:
            retn_func_count+=1
            found =[0]
            func_gadget_find(each_func,found)#check the function for gadgets
            for each_callee in each_func.callees:
                found[0] =0
                func_gadget_find(each_callee,found)#check each callee for gadgets
                if found[0] ==1:
                    print "[*] Function %s @ %s has a callee %s @ %s which seems useful"%(each_func.symbol.full_name,
                        hex(each_func.start), each_callee.symbol.full_name,hex(each_callee.start))

    print "[*] Found %s functions with the return instruction criteria"%(retn_func_count)

# loaded modules in IE 32 bit renderer process
binary_list = ['C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.1911.3-0\\X86\\MpOav.dll', 
'C:\\Windows\\SysWOW64\\jscript.dll', 'C:\\Windows\\SysWOW64\\efswrt.dll', 
'C:\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.18362.657_none_71d521d55ae5c7cf\\COMCTL32.dll',
 'C:\\Windows\\system32\\directmanipulation.dll', 'C:\\Windows\\SYSTEM32\\ninput.dll', 'C:\\Windows\\SYSTEM32\\IEUI.dll', 
 'C:\\Windows\\SYSTEM32\\MSHTML.dll', 'C:\\Windows\\System32\\IDStore.dll', 'C:\\Windows\\SysWOW64\\uiautomationcore.dll', 
 'C:\\Windows\\SYSTEM32\\DWrite.dll', 'C:\\Windows\\SYSTEM32\\d2d1.dll', 'C:\\Windows\\SYSTEM32\\apphelp.dll', 
 'C:\\Windows\\System32\\jscript9.dll', 'C:\\Windows\\SysWOW64\\sxs.dll', 'C:\\Windows\\SYSTEM32\\msIso.dll', 
 'C:\\Windows\\SysWOW64\\CoreUIComponents.dll', 'C:\\Windows\\system32\\dcomp.dll', 'C:\\Windows\\SysWOW64\\ntmarta.dll', 
 'C:\\Windows\\SysWOW64\\CoreMessaging.dll', 'C:\\Windows\\SYSTEM32\\dxgi.dll', 'C:\\Windows\\SYSTEM32\\IEFRAME.dll', 
 'C:\\Windows\\SysWOW64\\dispex.dll', 'C:\\Windows\\SysWOW64\\TextInputFramework.dll', 'C:\\Windows\\SYSTEM32\\dxcore.dll', 
 'C:\\Windows\\SYSTEM32\\d3d11.dll', 'C:\\Windows\\system32\\dataexchange.dll', 'C:\\Windows\\system32\\twinapi.appcore.dll',
  'C:\\Windows\\system32\\vm3dum_10.dll', 'C:\\Windows\\SysWOW64\\amsi.dll', 'C:\\Windows\\SYSTEM32\\WINNSI.DLL', 
  'C:\\Windows\\SYSTEM32\\ondemandconnroutehelper.dll', 'C:\\Windows\\SYSTEM32\\WKSCLI.DLL', 
  'C:\\Windows\\system32\\mswsock.dll', 'C:\\Windows\\system32\\RMCLIENT.dll', 'C:\\Windows\\SYSTEM32\\MLANG.dll', 
  'C:\\Windows\\SYSTEM32\\dbgcore.DLL', 'C:\\Windows\\SYSTEM32\\WINMMBASE.dll', 'C:\\Windows\\SYSTEM32\\WINMM.dll', 
  'C:\\Windows\\SYSTEM32\\dbghelp.dll', 'C:\\Windows\\SYSTEM32\\iertutil.dll', 'C:\\Windows\\SYSTEM32\\NETAPI32.dll', 
  'C:\\Windows\\SYSTEM32\\WINHTTP.dll', 'C:\\Windows\\system32\\uxtheme.dll', 
  'C:\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.18362.657_none_2e72ec50278a619e\\comctl32.dll', 
  'C:\\Windows\\SYSTEM32\\NETUTILS.DLL', 'C:\\Windows\\SYSTEM32\\urlmon.dll', 'C:\\Windows\\SYSTEM32\\Secur32.dll', 
  'C:\\Windows\\SYSTEM32\\dwmapi.dll', 'C:\\Windows\\System32\\SAMLIB.dll', 'C:\\Windows\\System32\\ieproxy.dll', 
  'C:\\Windows\\SysWOW64\\MPR.dll', 'C:\\Windows\\SysWOW64\\OneCoreUAPCommonProxyStub.dll', 'C:\\Windows\\SysWOW64\\WLDP.DLL',
   'C:\\Program Files (x86)\\Internet Explorer\\IEShims.dll', 'C:\\Windows\\SYSTEM32\\wintypes.dll', 
   'C:\\Windows\\system32\\rsaenh.dll', 'C:\\Windows\\System32\\vaultcli.dll', 
   'C:\\Windows\\System32\\OneCoreCommonProxyStub.dll', 'C:\\Windows\\SYSTEM32\\IPHLPAPI.DLL', 
   'C:\\Windows\\SYSTEM32\\ieapfltr.dll', 'C:\\Windows\\SYSTEM32\\tbs.dll', 'C:\\Windows\\SYSTEM32\\vm3dum_loader.dll', 
   'C:\\Windows\\SYSTEM32\\srpapi.dll', 'C:\\Windows\\SYSTEM32\\TOKENBINDING.dll', 'C:\\Windows\\system32\\msimtf.dll', 
   'C:\\Windows\\SYSTEM32\\PROPSYS.dll', 'C:\\Windows\\SYSTEM32\\USERENV.dll', 'C:\\Windows\\SYSTEM32\\WININET.dll', 
   'C:\\Windows\\SYSTEM32\\VERSION.dll', 'C:\\Windows\\System32\\CRYPTBASE.dll', 'C:\\Windows\\System32\\SspiCli.dll', 
   'C:\\Windows\\System32\\IMM32.DLL', 'C:\\Windows\\SysWOW64\\WINTRUST.dll', 'C:\\Windows\\System32\\msvcrt.dll', 
   'C:\\Windows\\System32\\kernel.appcore.dll', 'C:\\Windows\\System32\\windows.storage.dll', 'C:\\Windows\\System32\\combase.dll', 
   'C:\\Windows\\System32\\MSCTF.dll', 'C:\\Windows\\System32\\SHELL32.dll', 'C:\\Windows\\System32\\shcore.dll', 
   'C:\\Windows\\System32\\bcryptPrimitives.dll', 'C:\\Windows\\System32\\WS2_32.dll', 'C:\\Windows\\System32\\cfgmgr32.dll', 
   'C:\\Windows\\System32\\imagehlp.dll', 'C:\\Windows\\System32\\profapi.dll', 'C:\\Windows\\System32\\powrprof.dll', 
   'C:\\Windows\\System32\\ucrtbase.dll', 'C:\\Windows\\System32\\SHLWAPI.dll', 'C:\\Windows\\System32\\gdi32full.dll', 
   'C:\\Windows\\System32\\bcrypt.dll', 'C:\\Windows\\System32\\KERNEL32.DLL', 'C:\\Windows\\System32\\win32u.dll', 
   'C:\\Windows\\System32\\ADVAPI32.dll', 'C:\\Windows\\System32\\sechost.dll', 'C:\\Windows\\System32\\UMPDC.dll', 
   'C:\\Windows\\System32\\OLEAUT32.dll', 'C:\\Windows\\System32\\MSASN1.dll', 'C:\\Windows\\System32\\cryptsp.dll', 
   'C:\\Windows\\System32\\KERNELBASE.dll', 'C:\\Windows\\System32\\USER32.dll', 'C:\\Windows\\System32\\msvcp_win.dll', 
   'C:\\Windows\\System32\\GDI32.dll', 'C:\\Windows\\System32\\clbcatq.dll', 'C:\\Windows\\System32\\CRYPT32.dll', 
   'C:\\Windows\\System32\\ole32.dll', 'C:\\Windows\\System32\\RPCRT4.dll', 'C:\\Windows\\System32\\comdlg32.dll', 
   'C:\\Windows\\System32\\NSI.dll', 'C:\\Windows\\SYSTEM32\\ntdll.dll']

for each_bin in binary_list:
    print "\n\n[*] Analyzing Binary %s"%(each_bin)
    scan_binary(each_bin)


