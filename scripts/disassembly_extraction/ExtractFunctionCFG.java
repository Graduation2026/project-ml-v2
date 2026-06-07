import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

public class ExtractFunctionCFG extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("Missing arguments");
            return;
        }
        String outputDir = args[0];
        String tempJsonFp = args[1];

        // Parse JSON config
        String jsonContent = new String(Files.readAllBytes(Paths.get(tempJsonFp)));
        JsonObject config = new JsonParser().parse(jsonContent).getAsJsonObject();
        JsonArray targets = config.getAsJsonArray("targets");
        String binBasename = config.get("bin_basename").getAsString();

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        Gson gson = new Gson();

        println("TOTAL FUNCTIONS IN MANAGER: " + funcManager.getFunctionCount());
        
        FunctionIterator funcIter = funcManager.getFunctions(true);
        int funcCount = 0;
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String fname = func.getName();
            
            if (funcCount < 15) {
                println("FOUND FUNCTION: " + fname);
            }
            funcCount++;

            List<JsonObject> matchedTargets = new ArrayList<>();
            for (JsonElement tElem : targets) {
                JsonObject t = tElem.getAsJsonObject();
                String targetFunc = t.get("func").getAsString();
                
                boolean match = false;
                if (fname.equals(targetFunc)
                    || fname.endsWith(targetFunc)
                    || fname.contains(targetFunc + "(")
                    || fname.contains("::" + targetFunc)) {
                    match = true;
                } else {
                    int idx = fname.indexOf(targetFunc);
                    if (idx > 0 && Character.isDigit(fname.charAt(idx - 1))) {
                        match = true;
                    }
                }
                
                if (match) {
                    matchedTargets.add(t);
                }
            }

            if (matchedTargets.isEmpty()) {
                continue;
            }

            // Manually disassemble function by tracing branches (not calls)
            Address entry = func.getEntryPoint();
            Set<Address> seen = new HashSet<>();
            Deque<Address> worklist = new ArrayDeque<>();
            worklist.add(entry);

            while (!worklist.isEmpty()) {
                Address addr = worklist.poll();
                if (!seen.add(addr)) continue;

                // Disassemble just this one address (no flow-following)
                ghidra.app.cmd.disassemble.DisassembleCommand dcmd =
                    new ghidra.app.cmd.disassemble.DisassembleCommand(new AddressSet(addr), null, false);
                dcmd.applyTo(currentProgram, monitor);

                Instruction instr = listing.getInstructionAt(addr);
                if (instr == null) continue;

                // Follow fall-through (next sequential instruction)
                Address ft = instr.getFallThrough();
                if (ft != null && !seen.contains(ft)) worklist.add(ft);

                // Follow branch targets (JMP, JZ, JNZ, etc.) but NOT calls
                FlowType flowType = instr.getFlowType();
                if (!flowType.isCall()) {
                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address flowAddr : flows) {
                            if (!seen.contains(flowAddr)) worklist.add(flowAddr);
                        }
                    }
                }
            }

            // Build body from traced addresses
            AddressSet bodySet = new AddressSet();
            for (Address a : seen) {
                Instruction instr = listing.getInstructionAt(a);
                if (instr != null) {
                    bodySet.add(instr.getMinAddress(), instr.getMaxAddress());
                }
            }

            // Build CFG using traced body
            BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
            JsonArray nodes = new JsonArray();
            JsonArray edges = new JsonArray();
            Map<String, Integer> blocks = new HashMap<>();

            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(bodySet, monitor);
            int blockIndex = 0;
            List<CodeBlock> blockList = new ArrayList<>();
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blockList.add(block);
                blocks.put(block.getMinAddress().toString(), blockIndex);

                JsonArray instructions = new JsonArray();
                InstructionIterator instrIter = listing.getInstructions(block, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    instructions.add(instr.toString());
                }

                JsonObject node = new JsonObject();
                node.addProperty("id", blockIndex);
                node.add("instructions", instructions);
                nodes.add(node);

                blockIndex++;
            }

            for (int i = 0; i < blockList.size(); i++) {
                CodeBlock block = blockList.get(i);
                CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    String destAddr = ref.getDestinationAddress().toString();
                    if (blocks.containsKey(destAddr)) {
                        JsonArray edge = new JsonArray();
                        edge.add(i);
                        edge.add(blocks.get(destAddr));
                        edges.add(edge);
                    }
                }
            }

            // Write one output file per matched target
            for (JsonObject t : matchedTargets) {
                JsonObject out = new JsonObject();
                out.addProperty("function_name", fname);
                out.addProperty("cve_id", t.get("cve_id").getAsString());
                out.addProperty("label", t.get("label").getAsInt());
                out.addProperty("binary", binBasename);
                out.add("nodes", nodes);
                out.add("edges", edges);

                String safeFunc = t.get("func").getAsString().replace("/", "_").replace("\\", "_");
                String opt = t.has("opt") ? t.get("opt").getAsString() : "optX";
                String filename = String.format("%s_%s_%s_%s_%d.json",
                    t.get("cve_id").getAsString(), binBasename, safeFunc, opt, t.get("label").getAsInt());

                try (FileWriter writer = new FileWriter(new File(outputDir, filename))) {
                    gson.toJson(out, writer);
                }
            }
        }
    }
}
