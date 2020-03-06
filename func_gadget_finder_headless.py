import sys
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
    cfg_index = 0
    header_index = 0
    for index in range(0,len(data_vals)):
      if "Guard_Control_Flow_Function_Table" in str(data_vals[index]):
        cfg_index = index
      if "Load_Configuration_Directory_Table" in str(data_vals[index]):
        lcte_index = index
      if "PE32_Optional_Header" in str(data_vals[index]):
        header_index = index

    if cfg_index !=0 and lcte_index !=0:
        GuardCFFunctionTable_virtualAddress = data_keys[cfg_index]
        lcte_virtualAddress = data_keys[lcte_index]
        lcte = parse_data_view("Load_Configuration_Directory_Table",lcte_virtualAddress)
        br.offset = lcte.guardCFFunctionCount.address
        if "uint64_t" in str(lcte.guardCFFunctionCount.type):
            GuardCFFunctionTable_size = br.read64le()
        elif "uint32_t" in str(lcte.guardCFFunctionCount.type):
            GuardCFFunctionTable_size = br.read32le()
    elif header_index != 0:
        pe32_header_address = data_vals[header_index]
        pe32_header = parse_data_view("PE32_Optional_Header",pe32_header_address.address)
        loadConfigTableEntry = pe32_header.loadConfigTableEntry.address
        lcte = parse_data_view("PE_Data_Directory_Entry",loadConfigTableEntry)
        lcte_virtualAddress = byte_swap(lcte.virtualAddress)#RVA
        lcte_size = byte_swap(lcte.size)
        lcte_virtualAddress = lcte_virtualAddress + bv.start
        GuardCFFunctionTable_offset = bv.types["SIZE_T"].width * 4 #16/32
        GuardCFFunctionTable = parse_data_view("PE_Data_Directory_Entry", (lcte_virtualAddress + lcte_size +
            GuardCFFunctionTable_offset ))
        GuardCFFunctionTable_virtualAddress = byte_swap(GuardCFFunctionTable.virtualAddress)#RVA
        GuardCFFunctionTable_size = byte_swap(GuardCFFunctionTable.size)
    else:
        print "Couldnt Find PE32 header, exiting!"
        sys.exit()

    br.offset = GuardCFFunctionTable_virtualAddress

    #Find all functions within the CFG Table
    CFG_funcs = []
    for i in range(0, GuardCFFunctionTable_size):
        CFG_RVA = br.read32le()
        CFG_byte = br.read8()
        func_address = bv.get_function_at(bv.start + CFG_RVA)
        #if BN failed to identify a function there, create one
        if func_address ==None:
            bv.create_user_function(bv.start + CFG_RVA)
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
 'C:\\Windows\\SysWOW64\\directmanipulation.dll', 'C:\\Windows\\SysWOW64\\ninput.dll', 'C:\\Windows\\SysWOW64\\IEUI.dll', 
 'C:\\Windows\\SysWOW64\\MSHTML.dll', 'C:\\Windows\\SysWOW64\\IDStore.dll', 'C:\\Windows\\SysWOW64\\uiautomationcore.dll', 
 'C:\\Windows\\SysWOW64\\DWrite.dll', 'C:\\Windows\\SysWOW64\\d2d1.dll', 'C:\\Windows\\SysWOW64\\apphelp.dll', 
 'C:\\Windows\\SysWOW64\\jscript9.dll', 'C:\\Windows\\SysWOW64\\sxs.dll', 'C:\\Windows\\SysWOW64\\msIso.dll', 
 'C:\\Windows\\SysWOW64\\CoreUIComponents.dll', 'C:\\Windows\\SysWOW64\\dcomp.dll', 'C:\\Windows\\SysWOW64\\ntmarta.dll', 
 'C:\\Windows\\SysWOW64\\CoreMessaging.dll', 'C:\\Windows\\SysWOW64\\dxgi.dll', 'C:\\Windows\\SysWOW64\\IEFRAME.dll', 
 'C:\\Windows\\SysWOW64\\dispex.dll', 'C:\\Windows\\SysWOW64\\TextInputFramework.dll', 'C:\\Windows\\SysWOW64\\dxcore.dll', 
 'C:\\Windows\\SysWOW64\\d3d11.dll', 'C:\\Windows\\SysWOW64\\dataexchange.dll', 'C:\\Windows\\SysWOW64\\twinapi.appcore.dll',
  'C:\\Windows\\SysWOW64\\vm3dum_10.dll', 'C:\\Windows\\SysWOW64\\amsi.dll', 'C:\\Windows\\SysWOW64\\WINNSI.DLL', 
  'C:\\Windows\\SysWOW64\\ondemandconnroutehelper.dll', 'C:\\Windows\\SysWOW64\\WKSCLI.DLL', 
  'C:\\Windows\\SysWOW64\\mswsock.dll', 'C:\\Windows\\SysWOW64\\RMCLIENT.dll', 'C:\\Windows\\SysWOW64\\MLANG.dll', 
  'C:\\Windows\\SysWOW64\\dbgcore.DLL', 'C:\\Windows\\SysWOW64\\WINMMBASE.dll', 'C:\\Windows\\SysWOW64\\WINMM.dll', 
  'C:\\Windows\\SysWOW64\\dbghelp.dll', 'C:\\Windows\\SysWOW64\\iertutil.dll', 'C:\\Windows\\SysWOW64\\NETAPI32.dll', 
  'C:\\Windows\\SysWOW64\\WINHTTP.dll', 'C:\\Windows\\SysWOW64\\uxtheme.dll', 
  'C:\\Windows\\WinSxS\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.18362.657_none_2e72ec50278a619e\\comctl32.dll', 
  'C:\\Windows\\SysWOW64\\NETUTILS.DLL', 'C:\\Windows\\SysWOW64\\urlmon.dll', 'C:\\Windows\\SysWOW64\\Secur32.dll', 
  'C:\\Windows\\SysWOW64\\dwmapi.dll', 'C:\\Windows\\SysWOW64\\SAMLIB.dll', 'C:\\Windows\\SysWOW64\\ieproxy.dll', 
  'C:\\Windows\\SysWOW64\\MPR.dll', 'C:\\Windows\\SysWOW64\\OneCoreUAPCommonProxyStub.dll', 'C:\\Windows\\SysWOW64\\WLDP.DLL',
   'C:\\Program Files (x86)\\Internet Explorer\\IEShims.dll', 'C:\\Windows\\SysWOW64\\wintypes.dll', 
   'C:\\Windows\\SysWOW64\\rsaenh.dll', 'C:\\Windows\\SysWOW64\\vaultcli.dll', 
   'C:\\Windows\\SysWOW64\\OneCoreCommonProxyStub.dll', 'C:\\Windows\\SysWOW64\\IPHLPAPI.DLL', 
   'C:\\Windows\\SysWOW64\\ieapfltr.dll', 'C:\\Windows\\SysWOW64\\tbs.dll', 'C:\\Windows\\SysWOW64\\vm3dum_loader.dll', 
   'C:\\Windows\\SysWOW64\\srpapi.dll', 'C:\\Windows\\SysWOW64\\TOKENBINDING.dll', 'C:\\Windows\\SysWOW64\\msimtf.dll', 
   'C:\\Windows\\SysWOW64\\PROPSYS.dll', 'C:\\Windows\\SysWOW64\\USERENV.dll', 'C:\\Windows\\SysWOW64\\WININET.dll', 
   'C:\\Windows\\SysWOW64\\VERSION.dll', 'C:\\Windows\\SysWOW64\\CRYPTBASE.dll', 'C:\\Windows\\SysWOW64\\SspiCli.dll', 
   'C:\\Windows\\SysWOW64\\IMM32.DLL', 'C:\\Windows\\SysWOW64\\WINTRUST.dll', 'C:\\Windows\\SysWOW64\\msvcrt.dll', 
   'C:\\Windows\\SysWOW64\\kernel.appcore.dll', 'C:\\Windows\\SysWOW64\\windows.storage.dll', 'C:\\Windows\\SysWOW64\\combase.dll', 
   'C:\\Windows\\SysWOW64\\MSCTF.dll', 'C:\\Windows\\SysWOW64\\SHELL32.dll', 'C:\\Windows\\SysWOW64\\shcore.dll', 
   'C:\\Windows\\SysWOW64\\bcryptPrimitives.dll', 'C:\\Windows\\SysWOW64\\WS2_32.dll', 'C:\\Windows\\SysWOW64\\cfgmgr32.dll', 
   'C:\\Windows\\SysWOW64\\imagehlp.dll', 'C:\\Windows\\SysWOW64\\profapi.dll', 'C:\\Windows\\SysWOW64\\powrprof.dll', 
   'C:\\Windows\\SysWOW64\\ucrtbase.dll', 'C:\\Windows\\SysWOW64\\SHLWAPI.dll', 'C:\\Windows\\SysWOW64\\gdi32full.dll', 
   'C:\\Windows\\SysWOW64\\bcrypt.dll', 'C:\\Windows\\SysWOW64\\KERNEL32.DLL', 'C:\\Windows\\SysWOW64\\win32u.dll', 
   'C:\\Windows\\SysWOW64\\ADVAPI32.dll', 'C:\\Windows\\SysWOW64\\sechost.dll', 'C:\\Windows\\SysWOW64\\UMPDC.dll', 
   'C:\\Windows\\SysWOW64\\OLEAUT32.dll', 'C:\\Windows\\SysWOW64\\MSASN1.dll', 'C:\\Windows\\SysWOW64\\cryptsp.dll', 
   'C:\\Windows\\SysWOW64\\KERNELBASE.dll', 'C:\\Windows\\SysWOW64\\USER32.dll', 'C:\\Windows\\SysWOW64\\msvcp_win.dll', 
   'C:\\Windows\\SysWOW64\\GDI32.dll', 'C:\\Windows\\SysWOW64\\clbcatq.dll', 'C:\\Windows\\SysWOW64\\CRYPT32.dll', 
   'C:\\Windows\\SysWOW64\\ole32.dll', 'C:\\Windows\\SysWOW64\\RPCRT4.dll', 'C:\\Windows\\SysWOW64\\comdlg32.dll', 
   'C:\\Windows\\SysWOW64\\NSI.dll', 'C:\\Windows\\SysWOW64\\ntdll.dll']

for each_bin in binary_list:
    print "\n\n[*] Analyzing Binary %s"%(each_bin)
    scan_binary(each_bin)


