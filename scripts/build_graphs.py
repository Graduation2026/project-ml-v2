import json, os, torch
import numpy as np
from gensim.models import Word2Vec
from torch_geometric.data import Data

INPUT_DIR = "D:/ml_binpool_attempt/processed/functions"
OUTPUT_PT = "D:/ml_binpool_attempt/graphs/full_dataset.pt"
MODEL_PATH = "D:/ml_binpool_attempt/embeddings/model/asm2vec.model"

print("Loading Word2Vec model...")
w2v = Word2Vec.load(MODEL_PATH)
vector_size = w2v.vector_size

dataset = []
skipped_size = 0
os.makedirs(os.path.dirname(OUTPUT_PT), exist_ok=True)

for fname in os.listdir(INPUT_DIR):
    if not fname.endswith(".json"): continue
    
    with open(os.path.join(INPUT_DIR, fname)) as f:
        data = json.load(f)
        
    num_nodes = len(data["nodes"])
    if not (2 <= num_nodes <= 200):
        skipped_size += 1
        continue
        
    # Build node features
    x_list = []
    for node in data["nodes"]:
        node_vecs = []
        for instr in node["instructions"]:
            parts = instr.replace(",", " ").replace("[", " ").replace("]", " ").split()
            valid_parts = [p for p in parts if p in w2v.wv]
            if valid_parts:
                vec = np.mean([w2v.wv[p] for p in valid_parts], axis=0)
                node_vecs.append(vec)
        
        if node_vecs:
            node_feat = np.mean(node_vecs, axis=0)
        else:
            node_feat = np.zeros(vector_size)
        x_list.append(node_feat)
        
    x = torch.tensor(np.array(x_list), dtype=torch.float)
    
    # Build edge index
    edge_list = data.get("edges", [])
    if len(edge_list) > 0:
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
        
    # Extract metadata from filename: cve_basename_func_label.json
    # Split from right to avoid issues with underscores in cve or basename
    parts = fname[:-5].rsplit("_", 1)
    label = int(parts[1])
    
    cve_id = fname.split("_")[0]
    
    y = torch.tensor([label], dtype=torch.long)
    
    graph = Data(x=x, edge_index=edge_index, y=y)
    graph.cve_id = cve_id
    graph.fname = fname
    dataset.append(graph)

print(f"Built {len(dataset)} graphs. Skipped {skipped_size} due to node size filter (2-200).")
torch.save(dataset, OUTPUT_PT)
print(f"Saved dataset to {OUTPUT_PT}")
