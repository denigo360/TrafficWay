'use client';
import { useEffect, useState } from 'react';
import styles from './RequestLogArea.module.css';

export default function RequestLogArea({ captureId }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!captureId) return;
    setLoading(true);

    fetch(`/api/captures/${captureId}/logs`)
      .then((res) => res.json())
      .then((data) => {
        setLogs(data);
        setLoading(false);
      })
      .catch((err) => {
        setLoading(false);
      });
  }, [captureId]);

  return (
    <div className={styles.RequestLogContainer}>
      <h2 className={styles.title}>Request Log</h2>
      <div className={styles.Description}>
        <h3>id</h3>
        <h3>Source</h3>
        <h3>Destination</h3>
        <h3>Protocol</h3>
        <h3>Size</h3>
        <h3>Type</h3>
        <h3>Application</h3>
      </div>
      <div className={styles.LogEntries}>
        {loading ? (
          <p className={styles.status}>Loading...</p>
        ) : (
          logs.map((log) => (
            <div key={log.id} className={styles.LogLine}>
              <p>{log.id}</p>
              <p>{log.source}</p>
              <p>{log.destination}</p>
              <p>{log.app_name === 'UDP' || log.category_name === 'System' ? 'UDP' : 'TCP'}</p>
              <p>—</p>
              <p>{log.category_name}</p>
              <p className={styles.appHighlight}>{log.app_name}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
