from sqlalchemy import Column, Integer, String, Float
from database import Base

class TrafficFlow(Base):
    __tablename__ = "traffic_flows"

    id = Column(Integer, primary_key=True, index=True)
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

    def to_dict(self):
        return {
            "id": self.id,
            "source": f"{self.src_ip}:{self.src_port}",
            "destination": f"{self.dst_ip}:{self.dst_port}",
            "ja3_hash": self.ja3_hash,
            "sni": self.sni,
            "app_name": self.app_name,
            "category_name": self.category_name,
            "confidence": self.confidence
        }