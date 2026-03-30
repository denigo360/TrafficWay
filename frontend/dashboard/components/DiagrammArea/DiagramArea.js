'use client';

import styles from './DiagramArea.module.css';
import TrafficChart from '../../core/hooks/TrafficChart';
export default function DiagramArea() {
  return (
    <div className={styles.DiagramContainer}>
      <h2 className={styles.title}>Category Share </h2>
      <TrafficChart/>
    </div>
  );
}