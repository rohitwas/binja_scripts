"""
Binary Nijnja doesn't (yet) parse the full Load Config Directory Table for CFG compiled PE files. 
Issue filed here : https://github.com/Vector35/binaryninja-api/issues/1542

# Parse PE header, find load config directory table
# Parse CFG structure from lcdt and find cfg function table VA and size 
# Create a list of functions from CFG RVAs

"""

def parse_data_view(structure, address):
    PE = StructuredDataView(bv, structure, address)
    return PE

def byte_swap(i):
    i =str(i).replace(" ", "")
    temp = int (i,16)
    return struct.unpack("<I", struct.pack(">I", temp))[0]
 

lcte = parse_data_view("PE_Data_Directory_Entry",(bv.start + 0x1c8))
lcte_virtualAddress = byte_swap(lcte.virtualAddress)#RVA
lcte_size = byte_swap(lcte.size)
lcte_virtualAddress = lcte_virtualAddress + bv.start


GuardCFFunctionTable_offset = bv.types["SIZE_T"].width * 4 #16/32
GuardCFFunctionTable = parse_data_view("PE_Data_Directory_Entry", (lcte_virtualAddress + lcte_size + GuardCFFunctionTable_offset ))
GuardCFFunctionTable_virtualAddress = byte_swap(GuardCFFunctionTable.virtualAddress)#RVA
GuardCFFunctionTable_size = byte_swap(GuardCFFunctionTable.size)
br = BinaryReader(bv)
br.offset = (GuardCFFunctionTable_virtualAddress)

CFG_funcs = []
for i in range(0, GuardCFFunctionTable_size):
    CFG_RVA = br.read32le()
    CFG_byte = br.read8()
    CFG_funcs.append(bv.get_function_at(bv.start + CFG_RVA).symbol.full_name)

#set comment at each RVA to the corresponding function's full name
# for i in range(0,len(CFG_funcs)):
#     bv.set_comment_at(GuardCFFunctionTable_virtualAddress + i*5,CFG_funcs[i])



