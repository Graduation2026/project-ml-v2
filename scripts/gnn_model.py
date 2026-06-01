import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv, global_max_pool, global_mean_pool

class VulnGNN(torch.nn.Module):
    def __init__(self, input_dim=128, hidden_dim=64):
        super(VulnGNN, self).__init__()
        # Graph Attention Layers (GATv2 — dynamic attention)
        self.conv1 = GATv2Conv(input_dim, hidden_dim, heads=4, dropout=0.2)
        self.bn1   = nn.BatchNorm1d(hidden_dim * 4)
        self.conv2 = GATv2Conv(hidden_dim * 4, hidden_dim, heads=1, dropout=0.2)
        self.bn2   = nn.BatchNorm1d(hidden_dim)

        # Classifier
        # Input doubles because we concatenate max + mean pool
        self.fc1 = nn.Linear(hidden_dim * 2, hidden_dim)
        self.dropout = nn.Dropout(0.3)
        self.fc2 = nn.Linear(hidden_dim, 2)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.elu(x)

        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.elu(x)

        # Graph-level readout: concatenate max-pool and mean-pool
        x = torch.cat([global_max_pool(x, batch), global_mean_pool(x, batch)], dim=1)

        x = self.fc1(x)
        x = F.elu(x)
        x = self.dropout(x)
        x = self.fc2(x)
        return x
