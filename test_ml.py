import requests
import json

BASE_URL = 'http://localhost:8000/api/ml'

# 1. Prepare synthetic baseline training data (Normal network traffic patterns)
baseline_data = [
    [512.0, 2.0, 80.0],
    [1024.0, 5.0, 443.0],
    [256.0, 1.0, 22.0],
    [600.0, 3.0, 80.0],
    [800.0, 4.0, 443.0],
    [512.0, 2.0, 80.0],
    [1200.0, 6.0, 443.0],
    [300.0, 1.0, 22.0],
    [700.0, 3.0, 80.0],
    [900.0, 4.0, 443.0]
]

print('[*] Training Isolation Forest model via API...')
train_res = requests.post(f'{BASE_URL}/train', json=baseline_data)
print('Training Response:', train_res.json())

# 2. Test Normal Traffic Prediction
normal_sample = [550.0, 2.5, 80.0]
res_normal = requests.post(f'{BASE_URL}/detect', json=normal_sample)
print('\n[Test 1] Normal Traffic Sample:', res_normal.json())

# 3. Test Anomalous Traffic Prediction (Sudden high packet size / frequency spike)
anomalous_sample = [65000.0, 950.0, 3389.0]
res_anomaly = requests.post(f'{BASE_URL}/detect', json=anomalous_sample)
print('[Test 2] Anomalous Traffic Sample:', res_anomaly.json())
