from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class Capture(Base):
    __tablename__ = "captures"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    flows = relationship("TrafficFlow", back_populates="capture", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "datetime": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "flows_count": len(self.flows)
        }

class TrafficFlow(Base):
    __tablename__ = "traffic_flows"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(Integer, ForeignKey("captures.id"))
    
    src_ip = Column(String)
    src_port = Column(Integer)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    ja3_hash = Column(String, nullable=True)
    ja3_string = Column(String, nullable=True)
    sni = Column(String, nullable=True)
    app_name = Column(String, default="Unknown")
    category_name = Column(String, default="Traffic")
    confidence = Column(Float, default=0.0)

    capture = relationship("Capture", back_populates="flows")

    def to_dict(self):
        return {
            "id": self.id,
            "capture_id": self.capture_id,
            "source": f"{self.src_ip}:{self.src_port}",
            "destination": f"{self.dst_ip}:{self.dst_port}",
            "ja3_hash": self.ja3_hash,
            "sni": self.sni,
            "app_name": self.app_name,
            "category_name": self.category_name,
            "confidence": self.confidence
        }