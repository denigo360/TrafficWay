'use client';
import { useEffect, useState } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

export default function TrafficChart({ captureId }) {
  const [chartData, setChartData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!captureId) return;

    setLoading(true);
    fetch(`/api/captures/${captureId}/stats`)
      .then((res) => res.json())
      .then((data) => {
        const labels = data.map((item) => item.category);
        const values = data.map((item) => item.percentage);

        setChartData({
          labels: labels,
          datasets: [
            {
              label: 'Traffic Distribution (%)',
              data: values,
              backgroundColor: [
                'rgba(255, 99, 132, 0.6)', 
                'rgba(54, 162, 235, 0.6)', 
                'rgba(255, 206, 86, 0.6)', 
                'rgba(75, 192, 192, 0.6)', 
                'rgba(153, 102, 255, 0.6)', 
                'rgba(255, 255, 0, 0.6)'
              ],
              borderColor: 'rgba(255, 255, 255, 1)',
              borderWidth: 2,
            },
          ],
        });
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching stats:", err);
        setLoading(false);
      });
  }, [captureId]); 

  if (loading) return <p>Loading Chart...</p>;
  if (!chartData || chartData.labels.length === 0) return <p>No data</p>;

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          boxWidth: 15,
          padding: 15,
          font: {
            size: 12
          }
        }
      }
    },
    layout: {
      padding: {
        bottom: 20
      }
    }
  };

  return (
    <div style={{ position: 'relative', height: '100%', width: '100%' }}>
      <Doughnut data={chartData} options={options} />
    </div>
  );
}
