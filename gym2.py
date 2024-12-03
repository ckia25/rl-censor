# from strategy_encoder import strategy_encoder, decode_packets
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import random
from rl_training import Network, Critic, ContinuousActor
from evaluator import Evaluator
from strategycoding import NUM_PACKETS, PACKET_SIZE
from strategycoding import encode_state, decode_output, create_k_empty_response_packets
from packet import packet_summary

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

def reset_environment():
    base_packet = evaluator.get_base_packet()
    packets = [base_packet]*NUM_PACKETS
    response_packets = create_k_empty_response_packets(NUM_PACKETS)
    return base_packet, packets, response_packets


def episilon_greedy_experience(actor_network, packets, base_packet, response_packets, eps, evaluator):
    state_vector = encode_state(base_packet, packets, response_packets)
    r = random.random()
    if r < eps:
        outputs = actor_network(state_vector)
    else:
        outputs = torch.tensor(np.random.uniform(-2, 1, size=NUM_PACKETS*PACKET_SIZE)).float()
    modified_packets = decode_output(base_packet, packets, outputs)
    reward, response_packets = evaluator.evaluate(modified_packets)
    new_state_vector = encode_state(base_packet, modified_packets, response_packets)
    done = False
    return (state_vector, outputs, reward, new_state_vector, done), (modified_packets, response_packets)


def train_network(actor, critic, replay_buffer, actor_optimizer, critic_optimizer, batch_size, gamma, l2_lambda=1):
    
    batch = replay_buffer.sample(batch_size)
    states, actions, rewards, next_states, dones = zip(*batch)

    batch = replay_buffer.sample(batch_size)
    states, actions, rewards, next_states, dones = zip(*batch)

    states = torch.stack(states).float()
    actions = torch.stack(actions).float()
    rewards = torch.tensor(rewards, dtype=torch.float32).unsqueeze(1)
    next_states = torch.stack(next_states).float()
    dones = torch.tensor(dones, dtype=torch.float32).unsqueeze(1)
    
        # Compute target Q-values using critic
    with torch.no_grad():
        next_states_critic = next_states
        next_actions = actor(next_states_critic)
        target_q_values = rewards + gamma * (1 - dones) * critic(next_states_critic, next_actions)

    # Update critic: Minimize MSE between predicted and target Q-values
    predicted_q_values = critic(states, actions.clone().detach())
    critic_loss = nn.MSELoss()(predicted_q_values, target_q_values)
    # critic_loss += l2_lambda * torch.sum(torch.square(torch.tensor(list(critic.parameters()))))
    critic_optimizer.zero_grad()
    critic_loss.backward()
    critic_optimizer.step()
    
    # Update actor: Maximize the Q-value predicted by the critic
    actor_loss = -critic(states, actor(states)).mean()
    actor_optimizer.zero_grad()
    actor_loss.backward()

    actor_optimizer.step()


    print(torch.sum([val for val in actor.parameters()][1]))




if __name__ == "__main__":
    # Parameters
    state_dim = (2*NUM_PACKETS+1)*PACKET_SIZE
    action_dim = NUM_PACKETS*PACKET_SIZE  # Same as input_dim for vectorized actions
    n_hidden_layers = 2
    batch_size = 32
    gamma = 0.99
    lr = 0.001
    replay_buffer_capacity = 33

    # Initialize networks
    actor = ContinuousActor(state_dim, action_dim, hidden_layers=2, hidden_units=256)
    critic = Critic(state_dim, action_dim, hidden_layers=2, hidden_units=256)

    # Optimizer
    actor_optimizer = optim.Adam(actor.parameters(), lr=1e-4)
    critic_optimizer = optim.Adam(critic.parameters(), lr=1e-3)


    # Replay buffer
    replay_buffer = ReplayBuffer(replay_buffer_capacity)
    # torch.autograd.set_detect_anomaly(True)
    evaluator = Evaluator(censor_index=0)

    # Example loop for training
    eps = 10
    for episode in range(10000):
        base_packet, packets, response_packets = reset_environment()
        episode_reward = 0
        for step in range(4):
            # Simulate an environment (replace with real environment logic)
            experience, packet_info = episilon_greedy_experience(actor, packets, base_packet, response_packets, eps=eps, evaluator=evaluator)
            state, action, reward, next_state, done = experience    
            if reward > 0 or step == 3:
                done=True
            episode_reward += reward  
            if reward > 0:
                replay_buffer.push(state=state.clone(), action=action.clone(), reward=episode_reward, next_state=next_state.clone(),done=done)
                replay_buffer.push(state=state.clone(), action=action.clone(), reward=episode_reward, next_state=next_state.clone(),done=done)
                replay_buffer.push(state=state.clone(), action=action.clone(), reward=episode_reward, next_state=next_state.clone(),done=done)
            
            replay_buffer.push(state=state.clone(), action=action.clone(), reward=reward, next_state=next_state.clone(),done=done)
            
            # Train the learning network

            if len(replay_buffer) > batch_size:
                train_network(actor, critic, replay_buffer, actor_optimizer, critic_optimizer, batch_size, gamma)
            if done == True:
                break
            # Move to the next state
            packets, response_packets = packet_info
        
        if episode % 100 == 0 or episode_reward > 0:
            print('episode:',episode)
            packets, response_packets = packet_info
            print('*'*73)
            print("Current Reward", episode_reward)
            print('Base Packet')
            packet_summary(base_packet)
            print('Modified Packets')
            for packet in packets:
                packet_summary(packet)
            print('Response Packets')
            for packet in response_packets:
                packet_summary(packet)
            print('*'*73, flush=True)
            

    
    for i in range(3):
        experience, packet_info = episilon_greedy_experience(actor, packets, base_packet, response_packets, eps=10, evaluator=evaluator)
        packets, response_packets = packet_info
    print('*'*73)
    print("Current Reward", episode_reward)
    print('Base Packet')
    packet_summary(base_packet)
    print('Modified Packets')
    for packet in packets:
        packet_summary(packet)
    print('Response Packets')
    for packet in response_packets:
        packet_summary(packet)
    print('*'*73)     

