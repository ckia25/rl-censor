import torch
from torch.nn import nn

class Network(nn.Module):
    def __init__(self, input_dim, output_dim, n_hidden_layers):
        super(Network, self).__init__()
        self.input_layer = nn.Linear(input_dim, 256)
        self.hidden_layers = nn.ModuleList([
            nn.Linear(256, 256) for _ in range(n_hidden_layers)
        ])
        self.output_layer = nn.Linear(256, output_dim)
        self.activation = nn.ReLU()
    
    def forward(self, x):
        x = self.activation(self.input_layer(x))
        for layer in self.hidden_layers:
            x = self.activation(layer(x))
        x = self.output_layer(x)
        return x
    

    def load_parameters(self, other_model):
        try:
            self.load_state_dict(other_model.state_dict())
            print("Parameters successfully loaded from the other model.")
        except RuntimeError as e:
            print(f"Error loading parameters: {e}")
    


class Agent():


class Evaluator():

