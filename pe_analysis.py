import r2pipe
import json

# afl               - list all functions
# afll              - list all functions with metadata
# axt               - get xrefs from function? 
# pdf @0x18002adb8  - disassemble function at address
class PEAnalysis:
    def __init__(self, filepath):
        self.r2_rep = r2pipe.open(filepath)
        # init r2 analysis
        self.r2_rep.cmd("aaa")
        self.json_data = {}
        self.init_function_data()

        return 

    def init_function_data(self):
        attempts = 10
        while True:
            try:
                if attempts == 0:
                    exit()
                json_func_data = json.loads(self.r2_rep.cmd("aflj"))
            except:
                attempts-=1
                continue
            break
        
        for entry in json_func_data:
            entry_data = {}
            
            entry_data["fcn_name"] = entry["name"]
            entry_data["size"] = entry["realsz"]
            
            xref_list = self.generate_xrefs(entry)
            entry_data["xrefs"] = xref_list
            self.json_data[entry["offset"]] = entry_data 
        
        return 

    def generate_xrefs(self, entry):
        xrefs = self.r2_rep.cmd("axtj @0x%x" % int(entry["offset"]))
        json_loaded_xrefs = json.loads(xrefs)
        xref_list = []
        for xref in json_loaded_xrefs:
            xref_data = {}
            xref_data["from"] = xref["from"] 
            if "name" in xref:
                xref_data["fcn_name"] = xref["name"].split("+")[0]
            elif "fcn_name" in xref:
                xref_data["fcn_name"] = xref["fcn_name"]
            
            xref_list.append(xref_data)
        
        return xref_list

    def get_xref_list(self, target_addr):
        xrefs = []
        if target_addr in self.json_data:
            entry = self.json_data[target_addr]
            for xref in entry['xrefs']:
                xrefs.append(xref["from"])
        return xrefs

    def get_func_start_and_size_till_call(self, xref):
        func_start, func_end = self.get_func_start_and_size_till_end(xref)
        return func_start, xref-func_start

    def get_func_start_and_size_till_end(self, mem_addr):
        for func_start_addr, func_info in self.json_data.items():
            func_end_addr = func_start_addr + func_info["size"]
            if mem_addr > func_start_addr and mem_addr <= func_end_addr:
                return func_start_addr, func_end_addr
        
        return None, None
    
    def get_func_start(self, mem_addr):
        start_addrs = [x for x in self.json_data]
        start_addrs.sort()
        for i in range(len(start_addrs)-1):

            if start_addrs[i] < mem_addr < start_addrs[i+1]:
                return start_addrs[i]
        
        return None