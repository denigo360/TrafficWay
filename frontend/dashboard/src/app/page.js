'use client';

import { useState, useEffect } from "react";
import styles from "./page.module.css";
import DiagramArea from "../../components/DiagrammArea/DiagramArea";
import InfoArea from "../../components/InfoArea/InfoArea";
import RequestLogArea from "../../components/RequestLogArea/RequestLogArea";

export default function Home() {
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://127.0.0.1:8000/captures')
      .then((res) => res.json())
      .then((data) => {
        if (data && data.length > 0) {
          setSelectedCaptureId(data[0].id);
        }
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching captures:", err);
        setLoading(false);
      });
  }, []);

  return (
    <div className={styles.page}>
      <div className={styles.Title}>
        <h1>Network Traffic Analytics Dashboard</h1>
      </div>

      {loading ? (
        <p>Connecting to backend...</p>
      ) : selectedCaptureId ? (
        <>
          <div className={styles.GND}>
            <DiagramArea captureId={selectedCaptureId} />
            <InfoArea captureId={selectedCaptureId} />
          </div>

          <RequestLogArea captureId={selectedCaptureId} />
        </>
      ) : (
        <div className={styles.noData}>
          <h2>No Data Available</h2>
          <p>Please run the analysis script to populate the database.</p>
        </div>
      )}
    </div>
  );
}