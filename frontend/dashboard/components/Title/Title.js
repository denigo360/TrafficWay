'use client';
import styles from './Title.module.css';      
import Link from 'next/link';
export default function Title() {
    return (
    <div className={styles.Title}> 
        <Link href="/" className={styles.titleLink}>
                <h1>Network Traffic Analytics Dashboard</h1>
        </Link>    
    </div>
    )
}
