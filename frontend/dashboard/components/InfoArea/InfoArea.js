'use client';
import { useEffect, useState } from 'react';
import styles from './InfoArea.module.css';

export default function InfoArea({ captureId }) {
  const [stats, setStats] = useState({
    totalFlows: 0,
    uniqueIPs: 0,
    topApp: '—',
    primaryProtocol: '—'
  });

  useEffect(() => {
    if (!captureId) return;

    fetch(`http://127.0.0.1:8000/captures/${captureId}/summary`)
      .then((res) => res.json())
      .then((data) => {
        if (!data.error) {
          setStats({
            totalFlows: data.total_flows,
            uniqueIPs: data.unique_endpoints,
            topApp: data.top_app,
            primaryProtocol: data.primary_protocol
          });
        }
      })
      .catch((err) => console.error("Error fetching summary:", err));
  }, [captureId]);

  return (
    <div className={styles.GraphicContainer}>
      <h2 className={styles.title}>Session Intelligence</h2>
      <div className={styles.StatsGrid}>
        <div className={styles.StatCard}>
          <p>Total Flows</p>
          <strong>{stats.totalFlows}</strong>
        </div>
        <div className={styles.StatCard}>
          <p>Endpoints</p>
          <strong>{stats.uniqueIPs}</strong>
        </div>
        <div className={styles.StatCard}>
          <p>Primary App</p>
          <strong className={styles.blue}>{stats.topApp}</strong>
        </div>
        <div className={styles.StatCard}>
          <p>Primary Protocol</p>
          <strong className={styles.orange}>{stats.primaryProtocol}</strong>
        </div>
      </div>
    </div>
  );
}