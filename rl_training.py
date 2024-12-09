import torch
import torch.nn as nn
import numpy as np

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
        
        # We now have twice as many outputs:
        # - First half are for the mask (binary decision)
        # - Second half are for the values
        self.fc = nn.Sequential(*layers)
        self.mask_output_layer = nn.Linear(hidden_units, action_dim)    # action_dim = 24
        self.value_output_layer = nn.Linear(hidden_units, action_dim)   # action_dim = 24

    def forward(self, state):
        x = self.fc(state)
        mask_logits = self.mask_output_layer(x)   # Shape: (24,)
        values = self.value_output_layer(x)        # Shape: (24,)

        # Apply tanh only on the mask part
        mask = torch.tanh(mask_logits)
        # values remain unactivated or you can apply a suitable activation/clamping later

        # Concatenate mask and values back into a single vector if needed
        output = torch.cat([mask, values], dim=-1)  # Shape: (48,)

        return output

    

    @staticmethod
    def init_weights(m):
        if isinstance(m, nn.Linear):
            input_scale = 10000
            nn.init.uniform_(m.weight, -1 / input_scale, 1 / input_scale)
            nn.init.zeros_(m.bias)


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
        # self.apply(self.init_weights)


    @staticmethod
    def init_weights(m):
        if isinstance(m, nn.Linear):
            input_scale = 10000
            nn.init.uniform_(m.weight, -1 / input_scale, 1 / input_scale)
            nn.init.zeros_(m.bias)

    def forward(self, state, action):
        # Combine state and action
        state_action = torch.cat([state, action], dim=-1)
        # state_action = state_action
        return self.fc(state_action)  # Scalar Q-value



class RunningMeanStd:
    def __init__(self, shape):
        self.count = 1e-4
        self.mean = np.zeros(shape, dtype=np.float32)
        self.var = np.ones(shape, dtype=np.float32)
    
    def update(self, x):
        # x is of shape (batch_size, 60) in your case
        batch_mean = np.mean(x, axis=0)
        batch_var = np.var(x, axis=0)
        batch_count = x.shape[0]

        new_count = self.count + batch_count
        delta = batch_mean - self.mean
        m_a = self.var * self.count
        m_b = batch_var * batch_count
        M2 = m_a + m_b + delta**2 * self.count * batch_count / new_count

        self.mean = self.mean + (delta * batch_count / new_count)
        self.var = M2 / new_count
        self.count = new_count

    def normalize(self, x):
        # If x is a single state of shape (feature_dim,)
        # add a batch dimension to make it (1, feature_dim)
        single_state = False
        if x.ndim == 1:
            x = x[np.newaxis, :]
            single_state = True

        # Now x is guaranteed to be (batch_size, feature_dim)
        normalized = (x - self.mean) / (np.sqrt(self.var) + 1e-8)

        # If it was originally a single state, remove the batch dimension
        if single_state:
            normalized = normalized[0]

        return normalized




