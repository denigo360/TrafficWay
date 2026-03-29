'use client';

import styles from './RequestLogArea.module.css';

export default function RequestLogArea() {
  return (
    <div className={styles.RequestLogContainer}>
      <h2 className={styles.title}>Request Log</h2>
      <div className={styles.Description}>
        <h3>Time</h3>
        <h3>Source</h3>
        <h3>Destination</h3>
        <h3>Protocol</h3>
        <h3>Size</h3>
        <h3>Type</h3>
        <h3>Application</h3>
      </div>
    </div>
  );
}