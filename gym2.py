# from strategy_encoder import strategy_encoder, decode_packets
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import random
from rl_training import Network
from evaluator import Evaluator
from strategycoding import NUM_PACKETS, PACKET_SIZE
from strategycoding import encode_state, decode_output, create_k_empty_response_packets

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
        return random.sample(self.buffer, batch_size)
    
    def __len__(self):
        return len(self.buffer)

def episilon_greedy_experience(target_network, eps, evaluator, iterations, n=2):
    experience = []
    base_packet = evaluator.get_base_packet()
    packets = [base_packet]*NUM_PACKETS
    response_packets = create_k_empty_response_packets(NUM_PACKETS)
    state_vector = encode_state(base_packet, packets, response_packets)
    for i in range(iterations):
        r = random.random()
        if r < eps:
            outputs = target_network.forward(state_vector)
        else:
            outputs = torch.tensor(np.random.uniform(-1000000, 100000, size=len(state_vector))).float()
        modified_packets = decode_output(base_packet, packets, outputs)
        reward, response_packets = evaluator.evaluate(modified_packets)
        new_state_vector = encode_state(base_packet, modified_packets, response_packets)
        done = False
        if i == iterations - 1:
            done = True
        experience.append((state_vector, outputs, reward, new_state_vector, done))
        state_vector = new_state_vector
    return experience

def train_network(learning_network, target_network, replay_buffer, optimizer, batch_size, gamma):
    if len(replay_buffer) < batch_size:
        return  # Not enough samples yet

    # Sample a batch of experiences
    batch = replay_buffer.sample(batch_size)
    states, actions, rewards, next_states, dones = zip(*batch)
    

    # Convert to tensors
    states = torch.stack(states).float()
    actions = torch.stack(actions).float()
    rewards = torch.tensor(rewards, dtype=torch.float32).unsqueeze(1)
    next_states = torch.stack(next_states).float()
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
    loss.backward(retain_graph=True)
    optimizer.step()

    # NEED TO INCLUDE THE REWARD!!!!!!!!


if __name__ == "__main__":
    # Parameters
    input_dim = 10
    output_dim = 10  # Same as input_dim for vectorized actions
    n_hidden_layers = 2
    batch_size = 32
    gamma = 0.99
    lr = 0.001
    replay_buffer_capacity = 10000

    # Initialize networks
    learning_network = Network(input_dim, output_dim, n_hidden_layers)
    target_network = Network(input_dim, output_dim, n_hidden_layers)
    target_network.load_parameters(learning_network)  # Sync target network initially

    # Optimizer
    optimizer = optim.Adam(learning_network.parameters(), lr=lr)


    # Replay buffer
    replay_buffer = ReplayBuffer(replay_buffer_capacity)
    
    evaluator = Evaluator()
    good_example = ''
    print('Agent in the Gym')
    for i in range(10):
        experience = episilon_greedy_experience(
                                                agent_network=target_network,
                                                eps=0.9,
                                                evaluator=evaluator,
                                                iterations=10
                                                )
        if i % 100 == 0:
            print('Agent in round', i)
            print('reward', experience[-1][2])
            

        for tup in experience:
            state, action, reward, next_state, done = tup
            if reward > 100:
                print('*********************')
                print(reward)
                print(next_state)
                print('*********************')
            replay_buffer.push(
                state=state,
                action=action,
                reward=reward,
                next_state=next_state,
                done=done
            )
    print('Agent finished with the gym, length of replay buffer:', len(replay_buffer))
    print('Good Example:', good_example)


    # Example loop for training
    for episode in range(100):
        # Simulate an environment (replace with real environment logic)
        for t in range(50):
            experience = episilon_greedy_experience(
                                                    agent_network=target_network,
                                                    eps=0.9,
                                                    evaluator=evaluator,
                                                    iterations=10
                                                    )
                
            for tup in experience:
                state, action, reward, next_state, done = tup 
                if reward > 100:
                    print('Good Reward', reward)
                    print(next_state)
                                   
                replay_buffer.push(
                    state=state,
                    action=action,
                    reward=reward,
                    next_state=next_state,
                    done=done
                )

            # Train the learning network
            train_network(learning_network, target_network, replay_buffer, optimizer, batch_size, gamma)

            # Move to the next state
            state = next_state
        print("Current Reward", experience[-1][2])
        # Update the target network periodically
        if episode % 10 == 0:
            target_network.load_parameters(learning_network)
            print('parameters loaded')
