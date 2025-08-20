from flask import Flask, render_template_string, jsonify
import logging

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIDS Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: auto; background-color: #2c2c2c; padding: 20px; border-radius: 10px; box-shadow: 0 0 15px rgba(0,0,0,0.5); }
        h1, h2 { color: #4a90e2; border-bottom: 2px solid #4a90e2; padding-bottom: 10px; }
        .controls { margin-bottom: 20px; display: flex; gap: 10px; align-items: center; }
        button { background-color: #4a90e2; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 16px; transition: background-color 0.3s; }
        button:hover { background-color: #357abd; }
        button.stop { background-color: #e94b3c; }
        button.stop:hover { background-color: #c0392b; }
        #status { font-size: 18px; font-weight: bold; }
        #status.running { color: #2ecc71; }
        #status.stopped { color: #e94b3c; }
        .dashboard { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px;}
        .main-content { display: flex; flex-direction: column; gap: 20px; }
        .sidebar { display: flex; flex-direction: column; gap: 20px; }
        .panel { background-color: #333; padding: 20px; border-radius: 8px; }
        #alerts-log { list-style-type: none; padding: 0; max-height: 600px; overflow-y: auto; border: 1px solid #444; border-radius: 5px; padding: 10px; }
        #alerts-log li { background-color: #3a3a3a; margin-bottom: 10px; padding: 15px; border-radius: 5px; border-left: 5px solid #e94b3c; }
        #alerts-log li strong { color: #e94b3c; }
        .timestamp { font-size: 0.9em; color: #999; }
        #top-attackers-list { list-style-type: decimal; padding-left: 20px; }
        #top-attackers-list li { margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Advanced NIDS Dashboard</h1>
        <div class="controls">
            <button id="startButton">Start NIDS</button>
            <button id="stopButton" class="stop">Stop NIDS</button>
            <div id="status">Status: <span class="stopped">Stopped</span></div>
        </div>
        <div class="dashboard">
            <div class="main-content"><div class="panel"><h2>Live Alerts</h2><ul id="alerts-log"><li>No alerts yet.</li></ul></div></div>
            <div class="sidebar">
                <div class="panel"><h2>Alerts by Type</h2><canvas id="alertsChart"></canvas></div>
                <div class="panel"><h2>Top Attackers (by IP)</h2><ol id="top-attackers-list"></ol></div>
                <div class="panel"><h2>Metadata Logs</h2><p>DNS Queries Logged: <b id="dns-count">0</b></p><p>HTTP Requests Logged: <b id="http-count">0</b></p></div>
            </div>
        </div>
    </div>
    <script>
        const startButton = document.getElementById('startButton'), stopButton = document.getElementById('stopButton'), statusSpan = document.querySelector('#status span'), alertsLog = document.getElementById('alerts-log'), topAttackersList = document.getElementById('top-attackers-list'), dnsCountEl = document.getElementById('dns-count'), httpCountEl = document.getElementById('http-count');
        let alertsChart;
        function renderChart(data) { const ctx = document.getElementById('alertsChart').getContext('2d'); if (alertsChart) { alertsChart.destroy(); } alertsChart = new Chart(ctx, { type: 'bar', data: { labels: Object.keys(data), datasets: [{ label: '# of Alerts', data: Object.values(data), backgroundColor: 'rgba(74, 144, 226, 0.5)', borderColor: 'rgba(74, 144, 226, 1)', borderWidth: 1 }] }, options: { scales: { y: { beginAtZero: true, ticks: { color: '#e0e0e0' } }, x: { ticks: { color: '#e0e0e0' } } }, plugins: { legend: { display: false } } } }); }
        async function updateDashboard() { const [alertsRes, statsRes, logCountRes] = await Promise.all([fetch('/alerts'), fetch('/api/alert_stats'), fetch('/api/log_counts')]); const alerts = await alertsRes.json(); const stats = await statsRes.json(); const logCounts = await logCountRes.json(); alertsLog.innerHTML = alerts.length === 0 ? '<li>No alerts yet.</li>' : alerts.map(alert => `<li><strong>${alert.attack_type}</strong><br>${alert.details}<br><span class="timestamp">${new Date(alert.timestamp).toLocaleString()}</span></li>`).join(''); renderChart(stats.by_type); topAttackersList.innerHTML = stats.top_attackers.map(([ip, count]) => `<li>${ip} (${count} alerts)</li>`).join(''); dnsCountEl.textContent = logCounts.dns; httpCountEl.textContent = logCounts.http; }
        async function updateStatus() { const response = await fetch('/status'); const data = await response.json(); statusSpan.textContent = data.is_running ? 'Running on ' + data.interface : 'Stopped'; statusSpan.className = data.is_running ? 'running' : 'stopped'; }
        startButton.addEventListener('click', () => fetch('/start', { method: 'POST' }).then(updateStatus)); stopButton.addEventListener('click', () => fetch('/stop', { method: 'POST' }).then(updateStatus));
        updateStatus(); updateDashboard(); setInterval(updateDashboard, 3000); setInterval(updateStatus, 5000);
    </script>
</body>
</html>
"""

def create_app(nids_system):
    """Factory function to create the Flask app."""
    web_app = Flask(__name__)
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @web_app.route('/')
    def index(): return render_template_string(HTML_TEMPLATE)

    @web_app.route('/start', methods=['POST'])
    def start_nids():
        nids_system.start()
        return jsonify({"status": "NIDS started"})

    @web_app.route('/stop', methods=['POST'])
    def stop_nids():
        nids_system.stop()
        return jsonify({"status": "NIDS stopped"})

    @web_app.route('/status')
    def get_status():
        return jsonify({"is_running": nids_system.is_running, "interface": nids_system.interface})

    @web_app.route('/alerts')
    def get_alerts():
        return jsonify(list(nids_system.logger.alerts_log))

    @web_app.route('/api/alert_stats')
    def get_alert_stats():
        return jsonify(nids_system.logger.get_alert_stats())

    @web_app.route('/api/log_counts')
    def get_log_counts():
        return jsonify(nids_system.logger.get_log_counts())

    return web_app
