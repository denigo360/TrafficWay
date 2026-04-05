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

# Настройка CORS для работы с фронтендом
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация таблиц при запуске
database.init_db()

@app.post("/analyze_local_pcap")
def analyze_local_pcap(db: Session = Depends(database.get_db)):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(base_dir, "DPI", "test.pcap")
    
    if not os.path.exists(pcap_path):
        print(f"[!] ОШИБКА: Файл не найден: {pcap_path}")
        raise HTTPException(status_code=404, detail="PCAP file not found")

    print(f"[*] ШАГ 1: Начало анализа. Файл: {pcap_path}")

    try:
        print("[*] ШАГ 2: Создание записи Capture в БД...")
        new_capture = models.Capture(
            name=f"Analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        db.add(new_capture)
        db.commit()
        db.refresh(new_capture)
        print(f"[+] ШАГ 3: Запись создана. ID сессии: {new_capture.id}")

        reassembler = TCPStreamReassembler()
        processed_udp_flows = set()
        udp_records = []
        pkt_count = 0

        print("[*] ШАГ 4: Открытие PcapReader и чтение пакетов...")
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                pkt_count += 1
                
                if pkt_count % 500 == 0:
                    print(f"    ...обработано пакетов: {pkt_count}")

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
        
        print(f"[+] ШАГ 5: Чтение завершено. Пакетов: {pkt_count}. TCP стримов: {len(reassembler.streams)}")

        print("[*] ШАГ 6: Реассемблинг и DPI анализ...")
        for i, stream_key in enumerate(reassembler.streams.keys()):
            if i % 10 == 0:
                print(f"    ...анализ TCP потока {i} из {len(reassembler.streams)}")
            
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
            
            # Базовая классификация по портам, если DPI не уверен
            if app_name in ['Other', 'HTTPS', 'Other TCP']:
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

        print("[*] ШАГ 7: Обработка UDP потоков...")
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

        print("[*] ШАГ 8: Финальный коммит в базу данных...")
        db.commit()
        print("[!] УСПЕХ: Анализ завершен, данные сохранены.")
        return {"status": "success", "capture_id": new_capture.id, "flows_count": len(reassembler.streams) + len(udp_records)}

    except Exception as e:
        print(f"[!!!] КРИТИЧЕСКАЯ ОШИБКА: {str(e)}")
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

@app.get("/captures/{capture_id}/summary")
def get_capture_summary(capture_id: int, db: Session = Depends(database.get_db)):
    flows = db.query(models.TrafficFlow).filter(models.TrafficFlow.capture_id == capture_id).all()
    if not flows:
        return {"error": "No data"}

    unique_ips = set()
    protocols = []
    app_names = []

    for f in flows:
        unique_ips.add(f.src_ip)
        unique_ips.add(f.dst_ip)
        
        if f.app_name in ['DNS', 'UDP', 'QUIC/HTTP3']:
            protocols.append("UDP")
        else:
            protocols.append("TCP")
        
        app_names.append(f.app_name)

    
    from collections import Counter
    top_app = Counter(app_names).most_common(1)[0][0]
    top_proto = Counter(protocols).most_common(1)[0][0]

    return {
        "total_flows": len(flows),
        "unique_endpoints": len(unique_ips),
        "top_app": top_app,
        "primary_protocol": top_proto  
    }