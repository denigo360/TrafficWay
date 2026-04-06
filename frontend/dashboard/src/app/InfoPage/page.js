'use client';

import { useState, useEffect } from "react";
import styles from "./InfoPage.module.css";
import DiagramArea from "../../../components/DiagrammArea/DiagramArea";
import InfoArea from "../../../components/InfoArea/InfoArea";
import RequestLogArea from "../../../components/RequestLogArea/RequestLogArea";

export default function InfoPage() {
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/captures')
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
