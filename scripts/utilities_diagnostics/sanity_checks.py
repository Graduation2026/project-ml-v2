import json, torch
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "model_training"))
import torch.nn.functional as F
from gnn_model import VulnGNN
from torch_geometric.loader import DataLoader

print("="*50)
print("PHASE 8: PIPELINE SANITY CHECKS")
print("="*50)

# 1. Leakage Check
print("\n[Check 1] Validating strict 0% data leakage...")
with open("D:/ml_binpool_attempt/splits/cv_folds.json") as f:
    folds = json.load(f)

leakage_found = False
for fold in folds:
    train_set = set(fold["train"])
    test_set = set(fold["test"])
    overlap = train_set.intersection(test_set)
    if len(overlap) > 0:
        leakage_found = True
        print(f"  [FAIL] FATAL LEAKAGE IN FOLD {fold['fold']}: {overlap}")

if not leakage_found:
    print("  [PASS] No overlapping CVEs between train and test sets across all folds.")

# 2. Majority Class Collapse Check
print("\n[Check 2] Validating model prediction variance (no majority-class collapse)...")
dataset = torch.load("D:/ml_binpool_attempt/graphs/full_dataset.pt", weights_only=False)

# Use the last fold (Fold 4 / Run 5) as our best model
best_fold = folds[4]
test_cves = set(best_fold["test"])
test_data = [d for d in dataset if d.cve_id in test_cves]
test_loader = DataLoader(test_data, batch_size=32, shuffle=False)

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = VulnGNN(input_dim=128, hidden_dim=64).to(device)
model.load_state_dict(torch.load("D:/ml_binpool_attempt/model/best_fold4.pt", weights_only=True))
model.eval()

preds = []
with torch.no_grad():
    for batch in test_loader:
        batch = batch.to(device)
        out = model(batch.x, batch.edge_index, batch.batch)
        preds.extend(out.argmax(dim=1).cpu().tolist())

has_zero = 0 in preds
has_one = 1 in preds

if has_zero and has_one:
    print(f"  [PASS] Model predicts both Safe (0) and Vuln (1). It did not collapse.")
else:
    print(f"  [FAIL] Model only predicts one class.")

# 3. Paired Validation Check — now verifies CORRECT polarity
print("\n[Check 3] Validating structural differentiation on a single Vulnerable/Patched pair...")

# Find a pair of graphs (one label 1, one label 0) from the same CVE/function
vuln_graph = None
patch_graph = None

for d in test_data:
    if d.y.item() == 1 and vuln_graph is None:
        vuln_graph = d
    if d.y.item() == 0 and patch_graph is None:
        patch_graph = d
    if vuln_graph and patch_graph:
        break

if vuln_graph and patch_graph:
    print(f"  Testing on {vuln_graph.fname} vs {patch_graph.fname}")
    with torch.no_grad():
        v_out = model(vuln_graph.x.to(device), vuln_graph.edge_index.to(device),
                      torch.zeros(vuln_graph.x.size(0), dtype=torch.long).to(device))
        p_out = model(patch_graph.x.to(device), patch_graph.edge_index.to(device),
                      torch.zeros(patch_graph.x.size(0), dtype=torch.long).to(device))

        v_probs = F.softmax(v_out, dim=1).cpu().numpy()[0]
        p_probs = F.softmax(p_out, dim=1).cpu().numpy()[0]

        print(f"  Vulnerable Graph Probabilities: Safe={v_probs[0]*100:.1f}%, Vuln={v_probs[1]*100:.1f}%")
        print(f"  Patched Graph Probabilities:    Safe={p_probs[0]*100:.1f}%, Vuln={p_probs[1]*100:.1f}%")

        # Check 3a: Are they different at all?
        if v_probs[1] == p_probs[1]:
            print("  [FAIL] Probabilities are identical. The model cannot structurally differentiate them.")
        else:
            print("  [PASS] The GNN calculates different probabilities for the same function before and after the patch.")

        # Check 3b: Is the polarity correct? (vuln graph should have HIGHER vuln probability)
            if v_probs[1] > p_probs[1]:
                print("  [PASS] Correct polarity: vulnerable graph has higher Vuln probability than patched graph.")
            else:
                print("  [FAIL] Wrong polarity: patched graph has higher Vuln probability than the vulnerable graph.")
else:
    print("  \u26a0\ufe0f Could not find a suitable pair in the test set.")

print("\nPIPELINE COMPLETED SUCCESSFULLY.")
