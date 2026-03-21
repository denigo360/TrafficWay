from sqlalchemy import Column, Integer, String, Float, DateTime, BigInteger
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class TrafficFlow(Base):
    __tablename__ = "traffic_flows"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    

    src_ip = Column(String)
    src_port = Column(Integer)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    protocol = Column(String)
    size_bytes = Column(BigInteger)
    
    
    app_name = Column(String, default="Analyzing...")
    category_name = Column(String, default="Processing...")
    confidence = Column(Float, default=0.0)

    def to_dict(self):
        return {
            "id": self.id,
            "time": self.timestamp.strftime("%H:%M:%S"),
            "source": f"{self.src_ip}.{self.src_port}",
            "destination": f"{self.dst_ip}.{self.dst_port}",
            "protocol": self.protocol,
            "size": f"{round(self.size_bytes / (1024*1024), 2)} MB",
            "type": self.category_name,
            "application": self.app_name,
            "confidence": self.confidence
        }