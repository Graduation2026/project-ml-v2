import json, os
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
output_dir   = args[0]
temp_json_fp = args[1]

with open(temp_json_fp, "r") as f:
    config = json.load(f)
targets = config["targets"]
bin_basename = config["bin_basename"]

monitor = ConsoleTaskMonitor()
block_model = BasicBlockModel(currentProgram)
func_manager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

for func in func_manager.getFunctions(True):
    fname = func.getName()
    
    # Substring matching for C++ demangled names (e.g. PdfInfo::GuessFormat(std::string))
    matched_targets = []
    for t in targets:
        # Match exactly or if fname ends with target name or contains "target("
        # We check both to be safe
        if fname == t["func"] or fname.endswith(t["func"]) or (t["func"] + "(" in fname) or ("::" + t["func"] in fname):
            matched_targets.append(t)
            
    if not matched_targets:
        continue

    nodes, edges, blocks = [], [], {}
    block_list = list(block_model.getCodeBlocksContaining(func.getBody(), monitor))

    for i, block in enumerate(block_list):
        instructions = []
        instr = listing.getInstructionAt(block.getMinAddress())
        while instr and block.contains(instr.getAddress()):
            instructions.append(str(instr))
            instr = instr.getNext()
        blocks[str(block.getMinAddress())] = i
        nodes.append({"id": i, "instructions": instructions})

    for i, block in enumerate(block_list):
        dests = block.getDestinations(monitor)
        while dests.hasNext():
            dest_addr = str(dests.next().getDestinationAddress())
            if dest_addr in blocks:
                edges.append([i, blocks[dest_addr]])

    # Write one output file per target that matched this function
    for t in matched_targets:
        out = {
            "function_name": fname, "cve_id": t["cve_id"], "label": t["label"],
            "binary": bin_basename, "nodes": nodes, "edges": edges
        }
        safe_func = t["func"].replace("/","_").replace("\\","_")
        filename = "{}_{}_{}_{}_{}.json".format(t['cve_id'], bin_basename, safe_func, t['opt'], t['label'])
        
        with open(os.path.join(output_dir, filename), "w") as f:
            json.dump(out, f)
