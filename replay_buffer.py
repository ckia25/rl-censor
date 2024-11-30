import torch
import torch.nn as nn
import torch.optim as optim
import random
import numpy as np

# Define Replay Buffer
class ReplayBuffer:
    def __init__(self, capacity):
        self.capacity = capacity
        self.buffer = []
    
    def push(self, state, action, reward, next_state, done):
        """Add a new experience to the buffer."""
        if len(self.buffer) >= self.capacity:
            self.buffer.pop(0)  # Remove oldest experience
        self.buffer.append((state, action, reward, next_state, done))
    
    def sample(self, batch_size):
        """Sample a batch of experiences."""
        sampled_batch = random.sample(self.buffer, batch_size)
        batch = [item.clone() if isinstance(item, torch.Tensor) else item for item in sampled_batch]
        return batch
    
    def __len__(self):
        return len(self.buffer)
