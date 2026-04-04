'use client';
import { useState, useEffect } from "react";
import styles from "./page.module.css";
import GraphicArea from "../../components/GraphicArea/GraphicArea";
import DiagramArea from "../../components/DiagrammArea/DiagramArea";
import RequestLogArea from "../../components/RequestLogArea/RequestLogArea";
import DragAndDrop from "../../components/DragAndDrop/DragAndDrop";
export default function Home() {
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);

  
  useEffect(() => {
    fetch('http://127.0.0.1:8000/captures')
      .then(res => res.json())
      .then(data => {
        if (data && data.length > 0) {
          setSelectedCaptureId(data[0].id); 
        }
      })
      .catch(err => console.error("Error fetching captures:", err));
  }, []);

  return (
    <div className={styles.page}>
      <h1 className={styles.Title}>Network Traffic Overview</h1>
    
      <div className={styles.GND}> 
        <GraphicArea/> 
        <DiagramArea/>
      </div>
      <RequestLogArea/>
    </div>
  );
}