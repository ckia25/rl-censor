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


def train_network(learning_network, target_network, replay_buffer, optimizer, batch_size, gamma):
    if len(replay_buffer) < batch_size:
        return  # Not enough samples yet

    # Sample a batch of experiences
    batch = replay_buffer.sample(batch_size)
    states, actions, rewards, next_states, dones = zip(*batch)

    # Convert to tensors
    states = torch.tensor(np.array(states), dtype=torch.float32)
    actions = torch.tensor(np.array(actions), dtype=torch.float32)
    rewards = torch.tensor(rewards, dtype=torch.float32).unsqueeze(1)
    next_states = torch.tensor(np.array(next_states), dtype=torch.float32)
    dones = torch.tensor(dones, dtype=torch.float32).unsqueeze(1)

    # Compute Q values for current states and actions
    predicted_actions = learning_network(states)

    # Compute target Q values
    with torch.no_grad():
        target_actions = target_network(next_states)
        max_next_q_values = target_actions.max(dim=1, keepdim=True)[0]  # Max Q for next state
        target_q_values = rewards + gamma * max_next_q_values * (1 - dones)

    # Compute loss (e.g., between predicted and actual actions)
    loss = nn.MSELoss()(predicted_actions, actions)

    # Backpropagation
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
