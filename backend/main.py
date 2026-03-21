from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import database, models

app = FastAPI(title="Traffic Analysis API")


database.init_db()

# Захват
@app.post("/register_new_flow")
def register_new_flow(
    src_ip: str, src_port: int, 
    dst_ip: str, dst_port: int, 
    protocol: str, size_bytes: int,
    db: Session = Depends(database.get_db)
):
    new_flow = models.TrafficFlow(
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        protocol=protocol, size_bytes=size_bytes
    )
    db.add(new_flow)
    db.commit()
    db.refresh(new_flow)
    return {"flow_id": new_flow.id}

#Анализз
@app.post("/update_classification")
def update_classification(
    flow_id: int, 
    app_name: str, 
    category_name: str, 
    confidence: float,
    db: Session = Depends(database.get_db)
):
    flow = db.query(models.TrafficFlow).filter(models.TrafficFlow.id == flow_id).first()
    if flow:
        flow.app_name = app_name
        flow.category_name = category_name
        flow.confidence = confidence
        db.commit()
        return {"status": True}
    return {"status": False, "error": "Flow not found"}

#Визуализация 
@app.get("/get_total_stats")
def get_total_stats(db: Session = Depends(database.get_db)):
    count = db.query(models.TrafficFlow).count()
    return {"total_count": count}

@app.get("/get_throughput_data")
def get_throughput_data(interval_sec: int = 1, db: Session = Depends(database.get_db)):
    
    now = datetime.utcnow()
    last_records = db.query(models.TrafficFlow).filter(
        models.TrafficFlow.timestamp >= now - timedelta(seconds=interval_sec)
    ).all()
    
    total_bytes = sum(f.size_bytes for f in last_records)
    
    mbit_s = (total_bytes * 8) / (1048576 * interval_sec)
    
    return [{"time": now.strftime("%H:%M:%S"), "mbit_s": round(mbit_s, 2)}]

@app.get("/get_flow_logs")
def get_flow_logs(limit: int = 20, db: Session = Depends(database.get_db)):
    flows = db.query(models.TrafficFlow).order_by(models.TrafficFlow.id.desc()).limit(limit).all()
    return [f.to_dict() for f in flows]