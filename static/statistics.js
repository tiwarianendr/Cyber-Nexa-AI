document.addEventListener("DOMContentLoaded", function () {
  // Read statistics sent by Flask
  const dataElement = document.getElementById("statistics-data");

  if (!dataElement) {
    console.error("Statistics data was not found.");
    return;
  }

  let stats;

  try {
    stats = JSON.parse(dataElement.textContent);
  } catch (error) {
    console.error("Unable to read statistics data:", error);
    return;
  }

  const urlTotal = Number(stats.url_total) || 0;
  const emailTotal = Number(stats.email_total) || 0;
  const totalScans = Number(stats.total_scans) || 0;
  const totalThreats = Number(stats.total_threats) || 0;

  const otherScans = Math.max(0, totalScans - totalThreats);

  // -----------------------------
  // Scan Distribution Chart
  // -----------------------------

  const scanCanvas = document.getElementById("scanChart");

  if (typeof Chart !== "undefined" && scanCanvas) {
    new Chart(scanCanvas, {
      type: "bar",

      data: {
        labels: ["URL Scans", "Email Analyses"],

        datasets: [
          {
            label: "Number of Scans",

            data: [urlTotal, emailTotal],

            backgroundColor: ["#22d3ee", "#818cf8"],

            borderRadius: 7,
            maxBarThickness: 70,
          },
        ],
      },

      options: {
        responsive: true,
        maintainAspectRatio: false,

        plugins: {
          legend: {
            display: false,
          },
        },

        scales: {
          y: {
            beginAtZero: true,

            ticks: {
              precision: 0,
              color: "#cbd5e1",
            },

            grid: {
              color: "rgba(148,163,184,0.15)",
            },
          },

          x: {
            ticks: {
              color: "#cbd5e1",
            },

            grid: {
              display: false,
            },
          },
        },
      },
    });
  } else {
    const errorElement = document.getElementById("scanChartError");

    if (errorElement) {
      errorElement.hidden = false;
    }
  }

  // -----------------------------
  // Threat Overview Chart
  // -----------------------------

  const threatCanvas = document.getElementById("threatChart");

  if (typeof Chart !== "undefined" && threatCanvas) {
    new Chart(threatCanvas, {
      type: "doughnut",

      data: {
        labels: ["Potential Threats", "Other Recorded Scans"],

        datasets: [
          {
            data: [totalThreats, otherScans],

            backgroundColor: ["#fb7185", "#34d399"],

            borderColor: "#0f172a",
            borderWidth: 3,
            hoverOffset: 8,
          },
        ],
      },

      options: {
        responsive: true,
        maintainAspectRatio: false,

        plugins: {
          legend: {
            position: "bottom",

            labels: {
              color: "#cbd5e1",
              padding: 18,
            },
          },
        },

        cutout: "65%",
      },
    });
  } else {
    const errorElement = document.getElementById("threatChartError");

    if (errorElement) {
      errorElement.hidden = false;
    }
  }

  // -----------------------------
  // Security Score Progress Bar
  // -----------------------------

  const scoreFill = document.getElementById("scoreFill");
  const scoreMessage = document.getElementById("scoreMessage");

  if (scoreFill) {
    let score = Number(scoreFill.dataset.score);

    if (!Number.isFinite(score)) {
      score = 0;
    }

    score = Math.max(0, Math.min(100, score));

    setTimeout(function () {
      scoreFill.style.width = score + "%";
    }, 100);

    if (scoreMessage) {
      if (totalScans === 0) {
        scoreMessage.textContent =
          "No scans recorded yet. Run a scan to generate statistics.";
      } else {
        scoreMessage.textContent =
          "Calculated summary: " +
          score +
          "/100 based on the current rule-based classifications.";
      }
    }
  }
});
