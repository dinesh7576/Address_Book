import os, math, json, csv
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.address import Address
from ghidra.program.model.mem import MemoryAccessException

# === Output Paths ===
base_dir = getSourceFile().getParentFile().getAbsolutePath()
json_path = os.path.join(base_dir, "firmware_analysis_report.json")
csv_path  = os.path.join(base_dir, "firmware_analysis_report.csv")

# === Results Container ===
results = {
    "debug_symbols": None,
    "high_entropy_regions": [],
    "suspicious_functions": [],
    "xor_functions": [],
    "crypto_constants": [],
    "complex_control_flow_blocks": 0
}

def log_console(msg):
    print(msg)

def estimate_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for val in freq.values():
        p = val / float(len(data))
        entropy -= p * math.log(p, 2)
    return entropy

def has_debug_symbols():
    symbols = currentProgram.getSymbolTable().getAllSymbols(True)
    for sym in symbols:
        if sym.getSymbolType() == SymbolType.FUNCTION:
            name = sym.getName()
            if not (name.startswith("FUN_") or name.startswith("sub_")):
                return True
    return False

def find_high_entropy_regions(threshold=7.5, min_len=256):
    mem = currentProgram.getMemory()
    for block in mem.getBlocks():
        if not block.isInitialized() or block.isExecute():
            continue
        try:
            data = bytearray(block.getSize())
            block.getBytes(block.getStart(), data)
        except MemoryAccessException:
            continue
        for i in range(0, len(data) - min_len, min_len):
            chunk = data[i:i + min_len]
            entropy = estimate_entropy(chunk)
            if entropy > threshold:
                addr = str(block.getStart().add(i))
                results["high_entropy_regions"].append({"address": addr, "entropy": round(entropy, 2)})
                add_bookmark(block.getStart().add(i), "High entropy region")

def list_suspicious_functions():
    funcs = currentProgram.getListing().getFunctions(True)
    for func in funcs:
        name = func.getName()
        if name.startswith("FUN_") or name.startswith("sub_"):
            results["suspicious_functions"].append({"name": name, "address": str(func.getEntryPoint())})
            add_bookmark(func.getEntryPoint(), "Unnamed function")

def detect_xor_operations():
    listing = currentProgram.getListing()
    funcs = listing.getFunctions(True)
    for func in funcs:
        instructions = listing.getInstructions(func.getBody(), True)
        for instr in instructions:
            mnemonic = instr.getMnemonicString().lower()
            if "xor" in mnemonic:
                results["xor_functions"].append({"name": func.getName(), "address": str(func.getEntryPoint())})
                add_bookmark(func.getEntryPoint(), "XOR usage")
                break

def detect_crypto_constants():
    mem = currentProgram.getMemory()
    aes_sbox = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    ])
    for block in mem.getBlocks():
        try:
            data = bytearray(block.getSize())
            block.getBytes(block.getStart(), data)
        except:
            continue
        if aes_sbox in data:
            addr = str(block.getStart())
            results["crypto_constants"].append({"address": addr, "type": "AES S-box"})
            add_bookmark(block.getStart(), "AES S-box constant")

def check_control_flow_complexity():
    model = BasicBlockModel(currentProgram)
    iter = model.getCodeBlocks(TaskMonitor.DUMMY)
    count = 0
    while iter.hasNext():
        block = iter.next()
        if block.getNumDestinations(TaskMonitor.DUMMY) > 2:
            count += 1
    results["complex_control_flow_blocks"] = count

def add_bookmark(addr, comment):
    bm = currentProgram.getBookmarkManager()
    bm.setBookmark(addr, "Analysis", "Suspicious", comment)

def save_results():
    # Save JSON
    with open(json_path, "w") as f:
        json.dump(results, f, indent=4)
    # Save CSV
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Category", "Name", "Address", "Detail"])
        for entry in results["suspicious_functions"]:
            writer.writerow(["Suspicious Function", entry["name"], entry["address"], ""])
        for entry in results["xor_functions"]:
            writer.writerow(["XOR Function", entry["name"], entry["address"], ""])
        for entry in results["crypto_constants"]:
            writer.writerow(["Crypto Constant", "", entry["address"], entry["type"]])
        for entry in results["high_entropy_regions"]:
            writer.writerow(["High Entropy", "", entry["address"], f"Entropy: {entry['entropy']}"])
        writer.writerow(["Control Flow Blocks >2", "", "", str(results["complex_control_flow_blocks"])])

# ============ Run All Checks ============
log_console("=== Firmware Security Analysis with Ghidra ===")
results["debug_symbols"] = has_debug_symbols()
log_console(f"Debug Symbols Present: {results['debug_symbols']}")
find_high_entropy_regions()
list_suspicious_functions()
detect_xor_operations()
detect_crypto_constants()
check_control_flow_complexity()
save_results()
log_console(f"JSON report: {json_path}")
log_console(f"CSV report: {csv_path}")
