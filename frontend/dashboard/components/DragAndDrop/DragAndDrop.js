'use client';
import { useState, useRef, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import styles from './DragAndDrop.module.css';

export default function DragAndDrop() {
  const [isDragActive, setIsDragActive] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [isLoaded, setIsLoaded] = useState(false);
  const [analyzingIndex, setAnalyzingIndex] = useState(null);
  const fileInputRef = useRef(null);
  const router = useRouter();

  useEffect(() => {
    const savedFiles = localStorage.getItem('traffic_uploaded_files');
    if (savedFiles) {
      try {
        setUploadedFiles(JSON.parse(savedFiles));
      } catch (e) {
        console.error("Ошибка парсинга localStorage:", e);
      }
    }
    setIsLoaded(true);
  }, []);

  useEffect(() => {
    if (!isLoaded) return; 

    const filesToSave = uploadedFiles.map(f => ({
      name: f.name,
      size: f.size,
      lastModified: f.lastModified,
      isAnalyzed: f.isAnalyzed || false,
      captureId: f.captureId || null // Сохраняем ID из базы
    }));
    
    localStorage.setItem('traffic_uploaded_files', JSON.stringify(filesToSave));
  }, [uploadedFiles, isLoaded]);

  const handleFiles = (newFiles) => {
    const filesArray = Array.from(newFiles);
    setUploadedFiles((prev) => [...prev, ...filesArray]);
  };

  const handleFileClick = async (index) => {
    if (analyzingIndex !== null) return;

    const fileToAnalyze = uploadedFiles[index];

    // Если файл уже был проанализирован, переходим по его конкретному ID
    if (fileToAnalyze.isAnalyzed && fileToAnalyze.captureId) {
      router.push(`/InfoPage?id=${fileToAnalyze.captureId}`);
      return;
    }

    if (!(fileToAnalyze instanceof File)) {
      alert("Для анализа выберите файл заново (сессия истекла)");
      return;
    }

    setAnalyzingIndex(index);
    const formData = new FormData();
    formData.append('file', fileToAnalyze);

    try {
      const response = await fetch('http://127.0.0.1:8000/analyze_pcap', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        
        const updated = [...uploadedFiles];
        updated[index].isAnalyzed = true;
        updated[index].captureId = data.capture_id; // Записываем ID, пришедший с бэкенда
        setUploadedFiles(updated);

        // Переходим на страницу с параметром ID
        router.push(`/InfoPage?id=${data.capture_id}`);
      } else {
        alert(`Ошибка при анализе файла ${fileToAnalyze.name}`);
        setAnalyzingIndex(null);
      }
    } catch (error) {
      console.error("Upload error:", error);
      alert("Не удалось связаться с сервером");
      setAnalyzingIndex(null);
    }
  };

  const handleDragOver = (e) => { e.preventDefault(); setIsDragActive(true); };
  const handleDragLeave = () => { setIsDragActive(false); };
  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files?.length > 0) handleFiles(e.dataTransfer.files);
  };

  const removeFile = (e, index) => {
    e.stopPropagation();
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  return (
    <div className={styles.wrapper}>
      <div 
        className={`${styles.dropZone} ${isDragActive ? styles.dropZoneActive : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current.click()}
      >
        <input 
          type="file" ref={fileInputRef} className={styles.hiddenInput} 
          onChange={(e) => handleFiles(e.target.files)} multiple accept=".pcap,.pcapng"
        />
        <button className={styles.uploadButton} onClick={(e) => { e.stopPropagation(); fileInputRef.current.click(); }}>
          Выбрать файлы
        </button>
        <p className={styles.hint}>или перетащите их сюда</p>
      </div>

      {uploadedFiles.length > 0 && (
        <div className={styles.fileContainer}>
          <h3 className={styles.listTitle}>Ready for Analysis (Click to start)</h3>
          <div className={styles.fileGrid}>
            {uploadedFiles.map((file, index) => (
              <div 
                key={`${file.name}-${index}`} 
                className={`${styles.fileCard} ${analyzingIndex === index ? styles.fileCardAnalyzing : ''} ${file.isAnalyzed ? styles.fileCardDone : ''}`}
                onClick={() => handleFileClick(index)}
              >
                <div className={styles.fileInfo}>
                  <span className={styles.fileName}>
                    {analyzingIndex === index ? "⏳ Analyzing..." : file.name}
                    {file.isAnalyzed && " ✅"}
                  </span>
                  <span className={styles.fileSize}>{(file.size / 1024).toFixed(1)} KB</span>
                </div>
                {analyzingIndex !== index && (
                  <button className={styles.deleteBtn} onClick={(e) => removeFile(e, index)}>✕</button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}