import json, torch
import torch.nn as nn
from torch_geometric.loader import DataLoader
from sklearn.metrics import (f1_score, accuracy_score, precision_score,
                             recall_score, roc_auc_score)
from gnn_model import VulnGNN
from torch_geometric.utils import dropout_edge
from collections import Counter
from sklearn.model_selection import StratifiedShuffleSplit

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Using device: {device}")

dataset = torch.load("D:/ml_binpool_attempt/graphs/full_dataset.pt", weights_only=False)

with open("D:/ml_binpool_attempt/splits/cv_folds.json") as f:
    folds = json.load(f)

all_fold_results = []

for fold in folds:
    print(f"\n{'='*40}")
    print(f"FOLD {fold['fold']}")
    print(f"{'='*40}")

    train_cves = set(fold["train"])
    test_cves  = set(fold["test"])

    train_data = [d for d in dataset if d.cve_id in train_cves]
    test_data  = [d for d in dataset if d.cve_id in test_cves]

    # Stratified train/val split (maintains label proportions)
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=0.1, random_state=42)
    train_labels = [d.y.item() for d in train_data]
    train_idx, val_idx = next(splitter.split(train_data, train_labels))
    all_train = train_data
    train_data = [all_train[i] for i in train_idx]
    val_data   = [all_train[i] for i in val_idx]

    fold_labels = [d.y.item() for d in train_data]
    counts      = Counter(fold_labels)
    print(f"  Train balance: {counts}")
    print(f"  Validation samples: {len(val_data)}")

    train_loader = DataLoader(train_data, batch_size=32, shuffle=True)
    val_loader   = DataLoader(val_data,   batch_size=32, shuffle=False)
    test_loader  = DataLoader(test_data,  batch_size=32, shuffle=False)

    # Fresh model for each fold
    model     = VulnGNN(input_dim=128, hidden_dim=64).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=5e-4)

    # Class-weighted loss to handle any residual imbalance
    n_total = counts[0] + counts[1]
    weight  = torch.tensor([n_total / (2 * counts[1]),
                            n_total / (2 * counts[0])], dtype=torch.float).to(device)
    criterion = nn.CrossEntropyLoss(weight=weight)

    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="max", patience=7, factor=0.5)

    best_val_f1, patience_counter = 0, 0

    for epoch in range(150):
        model.train()
        total_loss = 0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()

            # Drop 10% of edges — lighter regularization for small-graph stability
            edge_index, _ = dropout_edge(
                batch.edge_index, p=0.1, training=True)

            out  = model(batch.x, edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        model.eval()
        preds, truths, probs = [], [], []
        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(device)
                out   = model(batch.x, batch.edge_index, batch.batch)
                preds.extend(out.argmax(dim=1).cpu().tolist())
                truths.extend(batch.y.cpu().tolist())
                probs.extend(torch.softmax(out, dim=1)[:, 1].cpu().tolist())

        val_f1 = f1_score(truths, preds, zero_division=0)
        scheduler.step(val_f1)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            torch.save(model.state_dict(),
                f"D:/ml_binpool_attempt/model/best_fold{fold['fold']}.pt")
            patience_counter = 0
        else:
            patience_counter += 1

        if patience_counter >= 15:
            print(f"Early stop at epoch {epoch}")
            break

    # Evaluate on test set for this fold
    model.load_state_dict(torch.load(
        f"D:/ml_binpool_attempt/model/best_fold{fold['fold']}.pt"))
    model.eval()

    preds, truths, probs = [], [], []
    with torch.no_grad():
        for batch in test_loader:
            batch = batch.to(device)
            out   = model(batch.x, batch.edge_index, batch.batch)
            preds.extend(out.argmax(dim=1).cpu().tolist())
            truths.extend(batch.y.cpu().tolist())
            probs.extend(torch.softmax(out, dim=1)[:, 1].cpu().tolist())

    results = {
        "fold":      fold["fold"],
        "accuracy":  accuracy_score(truths, preds),
        "precision": precision_score(truths, preds, zero_division=0),
        "recall":    recall_score(truths, preds, zero_division=0),
        "f1":        f1_score(truths, preds, zero_division=0),
        "auc_roc":   roc_auc_score(truths, probs)
    }
    all_fold_results.append(results)
    print(f"Fold {fold['fold']} Results: {results}")

# Final averaged results
print("\n" + "="*40)
print("CROSS-VALIDATION FINAL RESULTS")
print("="*40)
for metric in ["accuracy", "precision", "recall", "f1", "auc_roc"]:
    scores = [r[metric] for r in all_fold_results]
    avg    = sum(scores) / len(scores)
    std    = (sum((s-avg)**2 for s in scores)/len(scores))**0.5
    print(f"{metric.capitalize():12s}: {avg:.4f} ± {std:.4f}")
