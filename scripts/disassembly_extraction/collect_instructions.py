import json, os

all_sequences = []

for fname in os.listdir("D:/ml_binpool_attempt/processed/functions/"):
    if not fname.endswith(".json"):
        continue

    with open(f"D:/ml_binpool_attempt/processed/functions/{fname}") as f:
        data = json.load(f)

    for node in data["nodes"]:
        tokens = []
        for instr in node["instructions"]:
            parts = instr.replace(",", " ").replace("[", " ").replace("]", " ").split()
            tokens.extend(parts)
        if tokens:
            all_sequences.append(tokens)

print(f"Total sequences collected: {len(all_sequences)}")
