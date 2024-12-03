import torch
import torch.nn as nn

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



class ContinuousActor(nn.Module):
    def __init__(self, state_dim, action_dim, hidden_layers=2, hidden_units=256):
        super(ContinuousActor, self).__init__()
        layers = []
        
        # Input layer
        layers.append(nn.Linear(state_dim, hidden_units))
        layers.append(nn.ReLU())
        
        # Hidden layers
        for _ in range(hidden_layers - 1):
            layers.append(nn.Linear(hidden_units, hidden_units))
            layers.append(nn.ReLU())
        
        # Output layer
        layers.append(nn.Linear(hidden_units, action_dim))
        # layers.append(nn.Tanh())  # Maps actions to [-1, 1]
        
        self.fc = nn.Sequential(*layers)

    def forward(self, state):
        return self.fc(state)  # Continuous vector of actions


class Critic(nn.Module):
    def __init__(self, state_dim, action_dim, hidden_layers=2, hidden_units=256):
        super(Critic, self).__init__()
        layers = []
        
        # Input layer (combines state and action)
        layers.append(nn.Linear(state_dim + action_dim, hidden_units))
        layers.append(nn.ReLU())
        
        # Hidden layers
        for _ in range(hidden_layers - 1):
            layers.append(nn.Linear(hidden_units, hidden_units))
            layers.append(nn.ReLU())
        
        # Output layer (scalar Q-value)
        layers.append(nn.Linear(hidden_units, 1))
        
        self.fc = nn.Sequential(*layers)

    def forward(self, state, action):
        # Combine state and action
        state_action = torch.cat([state, action], dim=-1)
        return self.fc(state_action)  # Scalar Q-value



