'use client';
import { useState, useRef, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import styles from './DragAndDrop.module.css';

export default function DragAndDrop() {
  const [isDragActive, setIsDragActive] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [isLoaded, setIsLoaded] = useState(false); // Флаг для контроля синхронизации с памятью
  const [analyzingIndex, setAnalyzingIndex] = useState(null);
  const fileInputRef = useRef(null);
  const router = useRouter();

  // 1. ЗАГРУЗКА: При монтировании достаем список из localStorage
  useEffect(() => {
    const savedFiles = localStorage.getItem('traffic_uploaded_files');
    if (savedFiles) {
      try {
        const parsed = JSON.parse(savedFiles);
        setUploadedFiles(parsed);
      } catch (e) {
        console.error("Ошибка парсинга localStorage:", e);
      }
    }
    setIsLoaded(true); // Разрешаем сохранение после того, как попытка загрузки завершена
  }, []);

  // 2. СОХРАНЕНИЕ: Записываем метаданные при изменении списка
  useEffect(() => {
    if (!isLoaded) return; // Защита от затирания: не сохраняем, пока не подгрузили старое

    const filesToSave = uploadedFiles.map(f => ({
      name: f.name,
      size: f.size,
      lastModified: f.lastModified,
      isAnalyzed: f.isAnalyzed || false
    }));
    
    localStorage.setItem('traffic_uploaded_files', JSON.stringify(filesToSave));
  }, [uploadedFiles, isLoaded]);

  const handleFiles = (newFiles) => {
    const filesArray = Array.from(newFiles);
    // Добавляем новые файлы к текущим
    setUploadedFiles((prev) => [...prev, ...filesArray]);
  };

  const handleFileClick = async (index) => {
    if (analyzingIndex !== null) return;

    const fileToAnalyze = uploadedFiles[index];

    // Проверка: является ли объект реальным файлом (бинарным) или просто метаданными из localStorage
    if (!(fileToAnalyze instanceof File)) {
      alert("Для повторного анализа выберите файл заново (браузер не хранит содержимое файлов в памяти после перезагрузки)");
      return;
    }

    setAnalyzingIndex(index);
    const formData = new FormData();
    formData.append('file', fileToAnalyze);

    try {
      const response = await fetch('/api/analyze_pcap', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        // Помечаем файл как успешно проанализированный перед уходом со страницы
        const updated = [...uploadedFiles];
        updated[index].isAnalyzed = true;
        setUploadedFiles(updated);

        router.push('/InfoPage');
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

  const removeFile = (e, index) => {
    e.stopPropagation(); // Чтобы не запустился анализ при нажатии на крестик
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
          type="file" 
          className={styles.hiddenInput} 
          ref={fileInputRef} 
          onChange={(e) => handleFiles(e.target.files)}
          multiple 
          accept=".pcap,.pcapng"
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
                className={`
                    ${styles.fileCard} 
                    ${analyzingIndex === index ? styles.fileCardAnalyzing : ''} 
                    ${file.isAnalyzed ? styles.fileCardDone : ''}
                `}
                onClick={() => handleFileClick(index)}
              >
                <div className={styles.fileInfo}>
                  <span className={styles.fileName}>
                    {analyzingIndex === index ? "⏳ Analyzing..." : file.name}
                    {file.isAnalyzed && " ✅"}
                  </span>
                  <span className={styles.fileSize}>
                    {(file.size / 1024).toFixed(1)} KB
                  </span>
                </div>
                
                {analyzingIndex !== index && (
                  <button 
                    className={styles.deleteBtn} 
                    onClick={(e) => removeFile(e, index)}
                  >
                    ✕
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
