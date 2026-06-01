import json, torch, os
import matplotlib.pyplot as plt
from sklearn.metrics import (confusion_matrix, ConfusionMatrixDisplay,
                             f1_score, accuracy_score, precision_score,
                             recall_score, roc_auc_score)
from gnn_model import VulnGNN
from torch_geometric.loader import DataLoader

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}\n")

dataset = torch.load("D:/ml_binpool_attempt/graphs/full_dataset.pt", weights_only=False)
with open("D:/ml_binpool_attempt/splits/cv_folds.json") as f:
    folds = json.load(f)

model_dir = "D:/ml_binpool_attempt/model"
os.makedirs(model_dir, exist_ok=True)

all_results = []

for fold in folds:
    fold_id = fold["fold"]
    print(f"\n{'='*60}")
    print(f"EVALUATING FOLD {fold_id}")
    print(f"{'='*60}")

    test_cves = set(fold["test"])
    test_data = [d for d in dataset if d.cve_id in test_cves]
    test_loader = DataLoader(test_data, batch_size=32, shuffle=False)

    model = VulnGNN(input_dim=128, hidden_dim=64).to(device)
    ckpt_path = f"D:/ml_binpool_attempt/model/best_fold{fold_id}.pt"
    model.load_state_dict(torch.load(ckpt_path, weights_only=True))
    model.eval()

    preds, truths, probs, fnames = [], [], [], []

    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            out   = model(batch.x, batch.edge_index, batch.batch)
            preds.extend(out.argmax(dim=1).cpu().tolist())
            truths.extend(batch.y.cpu().tolist())
            probs.extend(torch.softmax(out, dim=1)[:, 1].cpu().tolist())
            fnames.extend(batch.fname)

    # Per-fold metrics
    metrics = {
        "fold":      fold_id,
        "accuracy":  accuracy_score(truths, preds),
        "precision": precision_score(truths, preds, zero_division=0),
        "recall":    recall_score(truths, preds, zero_division=0),
        "f1":        f1_score(truths, preds, zero_division=0),
        "auc_roc":   roc_auc_score(truths, probs)
    }
    all_results.append(metrics)

    cm = confusion_matrix(truths, preds)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                                  display_labels=["Safe (0)", "Vuln (1)"])
    disp.plot(cmap=plt.cm.Blues)
    plt.title(f"Confusion Matrix (Fold {fold_id})")
    cm_path = f"{model_dir}/confusion_matrix_fold{fold_id}.png"
    plt.savefig(cm_path)
    plt.close()
    print(f"  Saved: {cm_path}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1:        {metrics['f1']:.4f}")
    print(f"  AUC-ROC:   {metrics['auc_roc']:.4f}")

    # Show example predictions for this fold
    print(f"\n  Example predictions (Fold {fold_id}):")
    for i in range(min(5, len(preds))):
        status = "PASS" if preds[i] == truths[i] else "FAIL"
        clean_name = fnames[i].split("_", 1)[1].replace(".json", "")
        actual     = "Vuln" if truths[i] == 1 else "Safe"
        predicted  = "Vuln" if preds[i] == 1 else "Safe"
        print(f"    [{status}] {clean_name}: actual={actual} pred={predicted}")

# Final aggregated results
print("\n" + "="*60)
print("AGGREGATED CROSS-VALIDATION RESULTS")
print("="*60)
for metric in ["accuracy", "precision", "recall", "f1", "auc_roc"]:
    scores = [r[metric] for r in all_results]
    avg    = sum(scores) / len(scores)
    std    = (sum((s-avg)**2 for s in scores)/len(scores))**0.5
    print(f"{metric.capitalize():12s}: {avg:.4f} ± {std:.4f}")

# Save aggregated results as JSON
results_path = f"{model_dir}/evaluation_results.json"
with open(results_path, "w") as f:
    json.dump(all_results, f, indent=2)
print(f"\nSaved per-fold results to {results_path}")
