'use client';
import { useEffect, useState } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

export default function TrafficChart() {
  const [chartData, setChartData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/stats/categories')
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
              ],
              borderColor: 'rgba(255, 255, 255, 1)',
              borderWidth: 2,
            },
          ],
        });
        setLoading(false);
      })
      .catch((err) => console.error("Error fetching stats:", err));
  }, []);

  if (loading) return <p className="text-center">Loading Chart...</p>;

  return (
    <div className="p-4 bg-white rounded-lg shadow-md w-full max-w-md">
      <h2 className="text-xl font-bold mb-4 text-center text-gray-800">Traffic Classification</h2>
      <Doughnut 
        data={chartData} 
        options={{
          responsive: true,
          plugins: {
            legend: { position: 'bottom' },
          }
        }} 
      />
    </div>
  );
}
