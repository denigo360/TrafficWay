'use client';
import { useState, useEffect, Suspense } from "react";
import { useSearchParams } from 'next/navigation';
import styles from "./InfoPage.module.css";

// Импорты твоих компонентов (пути исправь под свою структуру)
import DiagramArea from "../../../components/DiagrammArea/DiagramArea";
import InfoArea from "../../../components/InfoArea/InfoArea";
import RequestLogArea from "../../../components/RequestLogArea/RequestLogArea";

function InfoPageContent() {
  const searchParams = useSearchParams();
  const targetId = searchParams.get('id'); // Читаем ?id=...
  
  const [selectedCaptureId, setSelectedCaptureId] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (targetId) {
      // Если ID есть в URL, используем его напрямую
      setSelectedCaptureId(parseInt(targetId));
      setLoading(false);
    } else {
      // Если ID нет (зашли просто так), берем последний из базы
      fetch('http://127.0.0.1:8000/captures/')
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
    }
  }, [targetId]);

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

// В Next.js использование useSearchParams требует Suspense
export default function InfoPage() {
  return (
    <Suspense fallback={<div>Loading Page...</div>}>
      <InfoPageContent />
    </Suspense>
  );
}