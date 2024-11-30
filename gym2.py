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
        outputs = actor_network.forward(state_vector)
    else:
        outputs = torch.tensor(np.random.uniform(-1000000, 100000, size=NUM_PACKETS*PACKET_SIZE)).float()
    modified_packets = decode_output(base_packet, packets, outputs*100000)
    reward, response_packets = evaluator.evaluate(modified_packets)
    new_state_vector = encode_state(base_packet, modified_packets, response_packets)
    done = False
    return (state_vector, outputs, reward, new_state_vector, done), (modified_packets, response_packets)


def train_network(actor, critic, replay_buffer, actor_optimizer, critic_optimizer, batch_size, gamma):
    
    batch = replay_buffer.sample(batch_size)
    states, actions, rewards, next_states, dones = zip(*batch)

    states = torch.stack(states).float().clone()
    actions = torch.stack(actions).float().clone()
    rewards = torch.tensor(rewards, dtype=torch.float32).unsqueeze(1).clone()
    next_states = torch.stack(next_states).float().clone()
    dones = torch.tensor(dones, dtype=torch.float32).unsqueeze(1).clone()
    
        # Compute target Q-values using critic
    with torch.no_grad():
        next_states_critic = next_states.clone()
        next_actions = actor(next_states)
        target_q_values = rewards + gamma * (1 - dones) * critic(next_states_critic, next_actions)

    # Update critic: Minimize MSE between predicted and target Q-values
    predicted_q_values = critic(states, actions)
    critic_loss = nn.MSELoss()(predicted_q_values, target_q_values)
    critic_optimizer.zero_grad()
    critic_loss.backward(retain_graph=True)
    critic_optimizer.step()

    # Update actor: Maximize the Q-value predicted by the critic
    actor_loss = -critic(states, actor(states).detach()).mean()
    actor_optimizer.zero_grad()
    actor_loss.backward(retain_graph=True)
    actor_optimizer.step()


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
    torch.autograd.set_detect_anomaly(True)
    evaluator = Evaluator(censor_index=1)

    # Example loop for training
    eps = 0.1
    for episode in range(1000):
        base_packet, packets, response_packets = reset_environment()
        episode_reward = 0
        eps += 0.0003
        for step in range(3):
            # Simulate an environment (replace with real environment logic)
            experience, packet_info = episilon_greedy_experience(actor, packets, base_packet, response_packets, eps=eps, evaluator=evaluator)
            state, action, reward, next_state, done = experience    
            if reward > 100:
                done=True
                replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
                replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
            replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
            episode_reward += reward  
            # Train the learning network
            if len(replay_buffer) > batch_size and done == True:
                train_network(actor, critic, replay_buffer, actor_optimizer, critic_optimizer, batch_size, gamma)
            if done == True:
                break
            # Move to the next state
            state = next_state.clone()
            packets, response_packets = packet_info
        
        if episode % 100 == 0 or episode_reward > 0:
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

