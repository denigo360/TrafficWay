import os
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from scapy.all import PcapReader, IP, TCP, UDP, Raw

import database
import models
from DPI.main import (
    TCPStreamReassembler, 
    find_client_hello_in_stream, 
    calculate_ja3, 
    extract_sni, 
    parse_client_hello_extensions,
    get_app_info
)

app = FastAPI(title="DPI Traffic Analysis System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

database.init_db()

@app.post("/analyze_local_pcap")
def analyze_local_pcap(db: Session = Depends(database.get_db)):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(base_dir, "DPI", "test.pcap")
    
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File not found at: {pcap_path}")
        raise HTTPException(status_code=404, detail=f"PCAP file not found")

    print(f"[*] Starting. File: {pcap_path}")

    try:
        print("[*] Creating Capture record in DB...")
        new_capture = models.Capture(
            name=f"Analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        db.add(new_capture)
        db.commit()
        db.refresh(new_capture)
        print(f"[+] Capture created. ID: {new_capture.id}")

        reassembler = TCPStreamReassembler()
        processed_udp_flows = set()
        udp_records = []
        pkt_count = 0

        print("[*] Reading packets with PcapReader...")
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                pkt_count += 1
                if not pkt.haslayer(IP):
                    continue
                
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if pkt.haslayer(TCP):
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                    if pkt.haslayer(Raw):
                        reassembler.add_packet(src_ip, dst_ip, sport, dport, pkt[TCP].seq, bytes(pkt[Raw]))
                
                elif pkt.haslayer(UDP):
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                    u_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
                    if u_key not in processed_udp_flows:
                        udp_records.append({"src": src_ip, "dst": dst_ip, "sport": sport, "dport": dport})
                        processed_udp_flows.add(u_key)
        
        print(f"[+] Packets processed: {pkt_count}. Streams found: {len(reassembler.streams)}")

        print("[*] Reassembling and analyzing TCP streams...")
        for stream_key in reassembler.streams.keys():
            stream_data = reassembler.get_reassembled_stream(stream_key)
            if not stream_data: continue

            try:
                (ip1, p1), (ip2, p2) = stream_key
            except: continue 

            client_hello = find_client_hello_in_stream(stream_data)
            sni, ja3_info = None, None
            
            if client_hello:
                exts = parse_client_hello_extensions(client_hello)
                sni = extract_sni(exts) if exts else None
                ja3_info = calculate_ja3(client_hello)
            
            app_data = get_app_info(
                ja3_hash=ja3_info['ja3_hash'] if ja3_info else None,
                ja3_info=ja3_info,
                sni=sni, src_ip=ip1, dst_ip=ip2
            )

            app_name = app_data.get('app', 'Other TCP')
            category = app_data.get('type', 'Network')
            
            if app_name in ['Other', 'HTTPS']:
                if 22 in [p1, p2]: app_name, category = "SSH", "Remote Access"
                elif 80 in [p1, p2]: app_name, category = "HTTP", "Web"

            db.add(models.TrafficFlow(
                capture_id=new_capture.id,
                src_ip=ip1, src_port=p1,
                dst_ip=ip2, dst_port=p2,
                ja3_hash=ja3_info['ja3_hash'] if ja3_info else None,
                ja3_string=ja3_info['ja3_string'] if ja3_info else "",
                sni=sni, app_name=app_name, category_name=category,
                confidence=1.0 if (client_hello or app_name != "Other TCP") else 0.4
            ))

        print("[*] Processing UDP flows...")
        for u in udp_records:
            u_app, u_cat = "UDP", "Network"
            if 53 in [u['sport'], u['dport']]: u_app, u_cat = "DNS", "System"
            elif 443 in [u['sport'], u['dport']]: u_app, u_cat = "QUIC/HTTP3", "Web"

            db.add(models.TrafficFlow(
                capture_id=new_capture.id,
                src_ip=u['src'], src_port=u['sport'],
                dst_ip=u['dst'], dst_port=u['dport'],
                app_name=u_app, category_name=u_cat, confidence=0.8
            ))

        print("[*] Committing to database...")
        db.commit()
        print("[!] DONE. Request finished.")
        return {"status": "success", "capture_id": new_capture.id, "flows_count": len(reassembler.streams) + len(udp_records)}

    except Exception as e:
        print(f"[FATAL ERROR] {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/captures")
def get_all_captures(db: Session = Depends(database.get_db)):
    return [c.to_dict() for c in db.query(models.Capture).order_by(models.Capture.timestamp.desc()).all()]

@app.get("/captures/{capture_id}/logs")
def get_capture_logs(capture_id: int, db: Session = Depends(database.get_db)):
    capture = db.query(models.Capture).filter(models.Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture session not found")
    return [flow.to_dict() for flow in capture.flows]

@app.get("/captures/{capture_id}/stats")
def get_capture_stats(capture_id: int, db: Session = Depends(database.get_db)):
    total = db.query(models.TrafficFlow).filter_by(capture_id=capture_id).count()
    if total == 0: return []
    res = db.query(models.TrafficFlow.category_name, func.count(models.TrafficFlow.id)).filter_by(capture_id=capture_id).group_by(models.TrafficFlow.category_name).all()
    return sorted([{"category": c, "count": n, "percentage": round((n/total)*100, 2)} for c, n in res], key=lambda x: x["count"], reverse=True)

@app.delete("/captures/{capture_id}")
def delete_capture(capture_id: int, db: Session = Depends(database.get_db)):
    capture = db.query(models.Capture).filter(models.Capture.id == capture_id).first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture session not found")
    db.delete(capture)
    db.commit()
    return {"status": "deleted"}