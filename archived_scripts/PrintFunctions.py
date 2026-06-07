import sys
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
func_manager = currentProgram.getFunctionManager()

count = 0
for func in func_manager.getFunctions(True):
    print("FUNC: " + func.getName())
    count += 1
    if count > 50:
        break
print("Total functions printed: " + str(count))
