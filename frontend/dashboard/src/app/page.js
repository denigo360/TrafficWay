'use client';
import { useState, useEffect } from "react";
import styles from "./page.module.css";
import GraphicArea from "../../components/GraphicArea/GraphicArea";
import DiagramArea from "../../components/DiagrammArea/DiagramArea";
import RequestLogArea from "../../components/RequestLogArea/RequestLogArea";

export default function Home() {
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    console.log("Fetching captures...");
    fetch('http://127.0.0.1:8000/captures')
      .then(res => {
        if (!res.ok) throw new Error("Backend return error");
        return res.json();
      })
      .then(data => {
        console.log("Data from backend:", data); // Посмотрим, что пришло
        if (data && data.length > 0) {
          console.log("Setting ID to:", data[0].id);
          setSelectedCaptureId(data[0].id);
        } else {
          console.log("No captures found in array");
        }
      })
      .catch(err => {
        console.error("Fetch error:", err);
        setError(err.message);
      });
  }, []);

  return (
    <div className={styles.page}>
      <h1>Network Traffic Overview</h1>
      
      {error && <p style={{color: 'red'}}>Error: {error}</p>}
      
      <p>Current ID: {selectedCaptureId || "Searching..."}</p>

      {selectedCaptureId ? (
        <>
          <div className={styles.GND}> 
            <GraphicArea captureId={selectedCaptureId} />
            <DiagramArea captureId={selectedCaptureId} />
          </div>
          <RequestLogArea captureId={selectedCaptureId} />
        </>
      ) : (
        <div className={styles.loadingBox}>
           <p>Waiting for data from ID: 7 (or latest)...</p>
           <button onClick={() => window.location.reload()}>Refresh Page</button>
        </div>
      )}
    </div>
  );
}