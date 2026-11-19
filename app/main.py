from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import redis

from app.database import init_db
from app.ml_engine import anomaly_detector
from app.services.suricata import get_latest_suricata_alerts
from app.services.mitigation import block_ip_address
from app.services.ml_engine import score_traffic_vector
from app.services.attack_chain import reconstruct_attack_chains

init_db()

redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[*] SENTINEL Enterprise NDR Backend Starting...")
    yield
    print("[*] Shutting down SENTINEL backend...")


app = FastAPI(
    title="SENTINEL - Intelligent Network Threat Detection & Response",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    return {
        "status": "active",
        "system": "SENTINEL NDR Node",
        "environment": "CachyOS Secure Enclave"
    }


@app.get("/api/alerts")
def get_alerts():
    alerts = get_latest_suricata_alerts()
    return {"status": "success", "count": len(alerts), "alerts": alerts}


@app.post("/api/ml/train")
async def train_model(data: list[list[float]]):
    success = anomaly_detector.train(data)
    if success:
        return {"status": "success", "message": "Isolation Forest model trained successfully."}
    return {"status": "error", "message": "Insufficient data for training (minimum 10 samples required)."}


@app.post("/api/ml/detect")
async def detect_anomaly(features: list[float]):
    result = anomaly_detector.predict(features)
    is_anomaly = (result == -1)
    return {
        "status": "success",
        "anomaly_detected": is_anomaly,
        "score": "High Risk" if is_anomaly else "Normal"
    }


class MitigationRequest(BaseModel):
    ip_address: str


@app.post("/api/mitigate/block")
def mitigate_block_ip(payload: MitigationRequest):
    result = block_ip_address(payload.ip_address)
    return result


class MLRequest(BaseModel):
    features: List[float]


@app.post("/api/ml/score")
def score_vector(payload: MLRequest):
    result = score_traffic_vector(payload.features)
    return result


@app.get("/api/threats/chains")
def get_attack_chains():
    chains = reconstruct_attack_chains()
    return {"status": "success", "count": len(chains), "attack_chains": chains}
