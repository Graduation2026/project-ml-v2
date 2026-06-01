# Sentinel AI (GNN Pipeline) — Binary Vulnerability Detection (v2)

Welcome to **Sentinel AI ML v2** — a deep learning binary vulnerability scanning system utilizing Graph Attention Networks (GATv2) and instruction embeddings to classify compiled basic-block Control Flow Graphs (CFGs) as Safe or Vulnerable.

---

## ─── SYSTEM OVERVIEW ─────────────────────────────────────────────────────────

Traditional binary scanners inspect superficial features (like strings or imports) or rely on rigid signatures. Sentinel AI analyzes the **Control Flow Graph (CFG)** structure of disassembled functions, converting disassembled instructions into node vectors and learning control-flow patterns via graph attention.

```
       [ Relocatable .o / Binary ]
                    │  (Headless Ghidra disassembler)
                    ▼
          [ Basic-Block CFG JSON ]
                    │  (Word2Vec Instruction Embedding)
                    ▼
        [ Node Attribute Matrix X ] + [ Edge Connections E ]
                    │
                    ▼
          [ PyTorch Geometric GNN ]
                    │  (GATv2Conv Layers + Global Pooling)
                    ▼
      [ Prediction: Safe / Vulnerable (89.1% Confidence) ]
```

---

## ─── REPOSITORY STRUCTURE ───────────────────────────────────────────────────

*   `artifacts/`: Contains pre-trained weights and evaluation results:
    *   `best_fold0.pt` to `best_fold4.pt`: Trained GNN model fold weights.
    *   `asm2vec.model`: Word2Vec instruction embedding model.
    *   `confusion_matrix_fold*.png`: Fold confusion matrix plots.
    *   `evaluation_results.json`: Detailed performance metrics per fold.
*   `scripts/`: Core pipeline execution scripts:
    *   `gnn_model.py`: PyTorch model class definition (`VulnGNN`).
    *   `build_graphs.py`: Converts raw basic block instruction JSONs from Ghidra into graph tensor structures.
    *   `train.py`: Multi-fold training pipeline using stratified K-fold cross-validation.
    *   `evaluate.py`: Generates the confusion matrices and final evaluation scores.
    *   `train_asm2vec.py`: Trains the Word2Vec model on corporate instruction corpora.
    *   `ExtractFunctionCFG.java` / `.py`: Headless Ghidra scripts to disassemble and extract CFGs from binpools.
    *   `test_single.py`: Direct CLI verification of a single processed graph.
*   `splits/`: JSON splits defining which binaries are assigned to train/test folds for reproducibility.
*   `binpool_info.json`: Master metadata file mapping function symbols inside compiled binaries to ground-truth vulnerability labels.

---

## ─── QUICK START GUIDE ───────────────────────────────────────────────────────

### Step 1: Create a Python Virtual Environment
Open a terminal in this directory and create a clean environment:

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies
Install PyTorch, PyTorch Geometric, Gensim, and scientific tools:

```bash
pip install -r requirements.txt
```

---

## ─── RUNNING THE PIPELINE ───────────────────────────────────────────────────

### Phase 1: Disassemble & Extract CFGs (Ghidra)
If you have raw compiled binaries and want to extract fresh CFG structures, install **Ghidra** and run the headless extractor:

```bash
python scripts/run_extraction.py
```
This saves block instructions and edges as JSON files into your local `/graphs/` folder.

### Phase 2: Build GNN-Ready Graphs
Convert the raw disassembler JSONs into GNN-ready node feature matrices and edge lists:

```bash
python scripts/build_graphs.py
```
This reads instruction tokens, vectorizes them using the Word2Vec model (`artifacts/asm2vec.model`), and outputs binary graph data files to the local `/processed/` folder.

### Phase 3: Train & Validate Models
To re-train the models using K-Fold Cross-Validation:

```bash
python scripts/train.py
```
This trains a **GATv2 Graph Attention Network** over 5 folds and saves the optimal weights `best_fold0.pt` ... `best_fold4.pt` into the `artifacts/` folder.

### Phase 4: Run Evaluation
To analyze performance and output confusion matrices:

```bash
python scripts/evaluate.py
```

---

## ─── PRE-TRAINED DEPLOYMENT IN PRODUCTION ───────────────────────────────────

> [!IMPORTANT]
> The absolute best-performing classifier checkpoint is **`best_fold4.pt`**. It has achieved **71.36% Accuracy**, **74.09% Precision** (low false alarms), and **79.91% AUC-ROC**.

When deploying this model inside a web service or backend runner (like `project-backend`), make sure to:
1.  Reference the model files relatively using `Path(__file__).resolve().parent.parent / "artifacts" / "best_fold4.pt"`.
2.  Use the `VulnGNN` class in `scripts/gnn_model.py` for standard class instantiation before loading state weights.
