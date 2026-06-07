import torch
from collections import Counter

dataset = torch.load("D:/ml_binpool_attempt/graphs/full_dataset.pt", weights_only=False)

labels = [d.y.item() for d in dataset]
counts = Counter(labels)

print(f"Total graphs: {len(dataset)}")
print(f"Safe (0): {counts[0]} ({counts[0]/len(dataset)*100:.1f}%)")
print(f"Vuln (1): {counts[1]} ({counts[1]/len(dataset)*100:.1f}%)")

if abs(counts[0] - counts[1]) / len(dataset) > 0.1:
    print("WARNING: Dataset is imbalanced. Oversampling logic will handle this inside the CV folds.")
else:
    print("Dataset is balanced.")
