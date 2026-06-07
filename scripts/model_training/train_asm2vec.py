import json, os
from gensim.models import Word2Vec

print("Loading sequences...")
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

print("Training Word2Vec model...")
model = Word2Vec(
    sentences=all_sequences,
    vector_size=128,
    window=10,
    min_count=5,
    workers=4,
    epochs=100,
    sg=1
)

os.makedirs("D:/ml_binpool_attempt/embeddings/model", exist_ok=True)
model.save("D:/ml_binpool_attempt/embeddings/model/asm2vec.model")
print(f"Saved. Vocabulary size: {len(model.wv)}")
