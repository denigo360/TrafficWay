'use client';
import { useState, useRef } from 'react';
import styles from './DragAndDrop.module.css';

export default function DragAndDrop() {
  const [isDragActive, setIsDragActive] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const fileInputRef = useRef(null);

  const handleFiles = (newFiles) => {
    const filesArray = Array.from(newFiles);
    setUploadedFiles((prev) => [...prev, ...filesArray]);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = () => {
    setIsDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files?.length > 0) {
      handleFiles(e.dataTransfer.files);
    }
  };

  const onButtonClick = (e) => {
    // Чтобы клик по кнопке не срабатывал дважды, если зона тоже имеет onClick
    e.stopPropagation();
    fileInputRef.current.click();
  };

  const removeFile = (index) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  return (
    <div className={styles.wrapper}>
      {/* Твоя зона Drag & Drop */}
      <div 
        className={`${styles.dropZone} ${isDragActive ? styles.dropZoneActive : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current.click()} // Зона теперь тоже кликабельна
      >
        <input 
          type="file" 
          className={styles.hiddenInput} 
          ref={fileInputRef} 
          onChange={(e) => handleFiles(e.target.files)}
          multiple 
        />
        
        <button className={styles.uploadButton} onClick={onButtonClick}>
          Загрузить файлы
        </button>
      </div>

      {/* Новый контейнер со списком */}
      {uploadedFiles.length > 0 && (
        <div className={styles.fileContainer}>
          <div className={styles.fileGrid}>
            {uploadedFiles.map((file, index) => (
              <div key={`${file.name}-${index}`} className={styles.fileCard}>
                <div className={styles.fileInfo}>
                  <span className={styles.fileName}>{file.name}</span>
                  <span className={styles.fileSize}>
                    {(file.size / 1024).toFixed(1)} KB
                  </span>
                </div>
                <button 
                  className={styles.deleteBtn} 
                  onClick={(e) => {
                    e.stopPropagation(); // Чтобы не открывался выбор файла
                    removeFile(index);
                  }}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}