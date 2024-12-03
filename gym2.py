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
import pandas as pd
import matplotlib.pyplot as plt

# Define Replay Buffer
class ReplayBuffer:
    def __init__(self, capacity, priority_capacity=50):
        self.capacity = capacity
        self.priority_capacity = priority_capacity
        self.buffer = []
        self.priority = []
        self.reward_sum = 0

    
    def push(self, state, action, reward, next_state, done):
        """Add a new experience to the buffer."""
        self.reward_sum += reward
        if len(self.buffer) >= self.capacity:
            removed_tup = self.buffer.pop(0)
            self.reward_sum -= removed_tup[2]
        tup = (state, action, reward, next_state, done)
        self.buffer.append(tup)
        if reward*self.__len__() > self.reward_sum:
            self.priority.append(tup)
            if len(self.priority) > self.priority_capacity:
                self.priority.pop(0)
    
    def sample(self, buffer_batch_size, priority_batch_size):
        """Sample a batch of experiences."""
        if len(self.priority) == 0:
            return random.sample(self.buffer, priority_batch_size+buffer_batch_size)
        return random.sample(self.buffer, buffer_batch_size) + random.choices(self.priority, k=priority_batch_size)
    
    def __len__(self):
        return len(self.buffer)

def reset_environment(evaluator):
    base_packet = evaluator.get_base_packet()
    packets = [base_packet]*NUM_PACKETS
    response_packets = create_k_empty_response_packets(NUM_PACKETS)
    return base_packet, packets, response_packets


def episilon_greedy_experience(actor_network, packets, base_packet, response_packets, eps, evaluator, mean=0, std_dev=100000):
    state_vector = encode_state(base_packet, packets, response_packets)
    r = random.random()
    if r < eps:
        outputs = actor_network(state_vector)
        noise = torch.tensor(np.random.normal(mean, std_dev, size=outputs.shape))
        noisy_outputs = outputs + noise
    else:
        noisy_outputs = torch.tensor(np.random.uniform(-30000, 10000, size=NUM_PACKETS*PACKET_SIZE)).float()
    modified_packets = decode_output(base_packet, packets, noisy_outputs)
    reward, response_packets = evaluator.evaluate(modified_packets)
    new_state_vector = encode_state(base_packet, modified_packets, response_packets)
    done = False
    return (state_vector, noisy_outputs, reward, new_state_vector, done), (modified_packets, response_packets)


def train_network(actor, critic, replay_buffer, actor_optimizer, critic_optimizer, batch_size, gamma, l2_lambda=1):
    
    batch = replay_buffer.sample(16, 16)
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





if __name__ == "__main__":
    # Parameters
    state_dim = (2*NUM_PACKETS+1)*PACKET_SIZE
    action_dim = NUM_PACKETS*PACKET_SIZE  # Same as input_dim for vectorized actions
    n_hidden_layers = 2
    batch_size = 32
    gamma = 0.99
    lr = 0.001
    replay_buffer_capacity = 10000

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
    eps = 0.9
    rewards = []
    max_reward = 0
    for episode in range(1000):
        base_packet, packets, response_packets = reset_environment(evaluator)
        episode_reward = 0
        for step in range(100):
            # Simulate an environment (replace with real environment logic)
            try:
                experience, packet_info = episilon_greedy_experience(actor, packets, base_packet, response_packets, eps=eps, evaluator=evaluator)
            except Exception as ex:
                continue
            state, action, reward, next_state, done = experience    
            if reward > max_reward:
                print(reward)
                done = True
                max_reward = reward
                replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
                replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
                replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
            if step == 99:
                done=True
            episode_reward += reward  

            replay_buffer.push(state=state, action=action, reward=reward, next_state=next_state,done=done)
            
            # Train the learning network

            if len(replay_buffer) > batch_size:
                train_network(actor, critic, replay_buffer, actor_optimizer, critic_optimizer, batch_size, gamma)
            packets, response_packets = packet_info
            average_reward = episode_reward/(step+1)
            if done == True:
                break
        

        # if episode % 100 == 0 or episode_reward > 0:
        #     print('episode:',episode)
        #     packets, response_packets = packet_info
        #     print('*'*73)
        #     print("Current Reward", episode_reward)
        #     print('Base Packet')
        #     packet_summary(base_packet)
        #     print('Modified Packets')
        #     for packet in packets:
        #         packet_summary(packet)
        #     print('Response Packets')
        #     for packet in response_packets:
        #         packet_summary(packet)
        #     print('*'*73, flush=True)
        rewards.append([average_reward])
        if len(rewards) % 10 == 0:
            plt.plot(np.arange(0, len(rewards), 1), rewards)
            plt.show()
            pd.DataFrame(rewards, columns=['reward']).to_csv('rewards.csv')
        if len(rewards) % 1000 == 0:
            pd.DataFrame(rewards, columns=['reward']).to_csv('rewards.csv')
    
        
            

    
    pd.DataFrame(rewards, columns=['reward']).to_csv('rewards.csv')

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

