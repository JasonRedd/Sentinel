from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
import redis
from contextlib import asynccontextmanager

redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print('[*] SENTINEL Enterprise NDR Backend Starting...')
    yield
    print('[*] Shutting down SENTINEL backend...')

app = FastAPI(
    title='SENTINEL - Intelligent Network Threat Detection & Response',
    version='1.0.0',
    lifespan=lifespan
)

@app.get('/health')
async def health_check():
    return {
        'status': 'active',
        'system': 'SENTINEL NDR Node',
        'environment': 'CachyOS Secure Enclave'
    }

@app.get('/api/alerts')
async def get_alerts(count: int = 20):
    try:
        streams = redis_client.xrevrange('sentinel:alerts', max='+', min='-', count=count)
        alerts = []
        for message_id, data in streams:
            alerts.append({
                'id': message_id,
                'timestamp': data.get('timestamp'),
                'src_ip': data.get('src_ip'),
                'dest_ip': data.get('dest_ip'),
                'signature': data.get('signature'),
                'severity': data.get('severity'),
                'category': data.get('category')
            })
        return {'status': 'success', 'count': len(alerts), 'alerts': alerts}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

from app.ml_engine import anomaly_detector

@app.post('/api/ml/train')
async def train_model(data: list[list[float]]):
    success = anomaly_detector.train(data)
    if success:
        return {'status': 'success', 'message': 'Isolation Forest model trained successfully.'}
    return {'status': 'error', 'message': 'Insufficient data for training (minimum 10 samples required).'}

@app.post('/api/ml/detect')
async def detect_anomaly(features: list[float]):
    result = anomaly_detector.predict(features)
    is_anomaly = (result == -1)
    return {
        'status': 'success',
        'anomaly_detected': is_anomaly,
        'score': 'High Risk' if is_anomaly else 'Normal'
    }

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)