(() => {
  const canvas = document.getElementById("payload-chart");
  const source = document.getElementById("payload-series");
  if (!canvas || !source || typeof Chart === "undefined") return;
  const series = JSON.parse(source.textContent);
  const styles = getComputedStyle(document.documentElement);
  const cyan = styles.getPropertyValue("--p-cyan").trim();
  const mint = styles.getPropertyValue("--p-mint").trim();
  const grid = "rgba(80, 110, 145, .16)";
  const muted = styles.getPropertyValue("--p-muted").trim();
  const context = canvas.getContext("2d");
  const gradient = context.createLinearGradient(0, 0, 0, 230);
  gradient.addColorStop(0, "rgba(34, 211, 238, .22)");
  gradient.addColorStop(1, "rgba(34, 211, 238, 0)");
  new Chart(context, {
    type: "line",
    data: {labels: series.map(item => item.day.slice(5)), datasets: [{
      label: "Hits", data: series.map(item => item.count), borderColor: cyan,
      backgroundColor: gradient, fill: true, borderWidth: 2, pointRadius: 2,
      pointHoverRadius: 5, pointBackgroundColor: mint, pointBorderColor: mint, tension: .28,
    }]},
    options: {
      responsive: true, maintainAspectRatio: false, animation: {duration: 180},
      interaction: {intersect: false, mode: "index"},
      plugins: {legend: {display: false}, tooltip: {
        backgroundColor: "#111a2b", borderColor: "#1a2540", borderWidth: 1,
        titleFont: {family: "JetBrains Mono", size: 11}, bodyFont: {family: "JetBrains Mono", size: 12},
        padding: 12, displayColors: false,
      }},
      scales: {
        x: {grid: {display: false}, ticks: {color: muted, maxTicksLimit: 7, font: {family: "JetBrains Mono", size: 9}}},
        y: {beginAtZero: true, grid: {color: grid}, border: {display: false}, ticks: {color: muted, precision: 0, font: {family: "JetBrains Mono", size: 9}}},
      },
    },
  });
})();
