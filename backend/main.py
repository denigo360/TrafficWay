import os
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from scapy.all import rdpcap, IP, TCP, Raw

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


database.init_db()

@app.post("/analyze_local_pcap")
def analyze_local_pcap(db: Session = Depends(database.get_db)):
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(base_dir, "DPI", "test.pcap")
    
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail=f"PCAP file not found at {pcap_path}")

    
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scapy error: {str(e)}")

    
    reassembler = TCPStreamReassembler()
    for pkt in pkts:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                reassembler.add_packet(
                    pkt[IP].src, pkt[IP].dst,
                    pkt[TCP].sport, pkt[TCP].dport,
                    pkt[TCP].seq, bytes(pkt[Raw])
                )

    added_count = 0
   
    for stream_key, _ in reassembler.streams.items():
        stream_data = reassembler.get_reassembled_stream(stream_key)
        if not stream_data or len(stream_data) < 50:
            continue

        client_hello = find_client_hello_in_stream(stream_data)
        if client_hello:
            extensions = parse_client_hello_extensions(client_hello)
            if extensions:
                sni = extract_sni(extensions)
                ja3_info = calculate_ja3(client_hello)
                
                ip1, port1 = stream_key[0]
                ip2, port2 = stream_key[1]

                
                app_data = get_app_info(
                    ja3_hash=ja3_info['ja3_hash'] if ja3_info else None,
                    ja3_info=ja3_info,
                    sni=sni,
                    src_ip=ip1,
                    dst_ip=ip2
                )

                
                flow = models.TrafficFlow(
                    src_ip=ip1,
                    src_port=port1,
                    dst_ip=ip2,
                    dst_port=port2,
                    ja3_hash=ja3_info['ja3_hash'] if ja3_info else None,
                    ja3_string=ja3_info['ja3_string'] if ja3_info else "",
                    sni=sni,
                    app_name=app_data.get('app', 'Other'),
                    category_name=app_data.get('type', 'Other'),
                    confidence=0.95 if app_data.get('detected_by') != 'none' else 0.4
                )
                db.add(flow)
                added_count += 1
    
    db.commit()
    return {"status": "success", "processed_streams": added_count}

@app.get("/logs")
def get_logs(db: Session = Depends(database.get_db)):
    flows = db.query(models.TrafficFlow).all()
    
    return [flow.to_dict() for flow in flows]