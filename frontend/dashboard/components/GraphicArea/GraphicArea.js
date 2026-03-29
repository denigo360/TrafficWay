'use client';

import styles from './GraphicArea.module.css';

export default function GraphicArea() {
  return (
    <div className={styles.GraphicContainer}>
      <h2 className={styles.title}>Traffic Activity over Time (Mbit/s)</h2>
    </div>
  );
}