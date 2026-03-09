const updateStats = async () => {
    try {
        const response = await fetch('/admin/db-stats');
        const data = await response.json();

        // Format the date nicely (e.g., Oct 24, 2023, 2:30 PM)
        const date = new Date(data.lastModified);
        document.getElementById('lastUpdated').textContent = date.toLocaleString();
        document.getElementById('dbSize').textContent = data.size;
    } catch (err) {
        document.getElementById('lastUpdated').textContent = "Error fetching stats";
    }
};

document.getElementById('downloadBtn').addEventListener('click', async () => {
    const status = document.getElementById('statusMessage');
    const btn = document.getElementById('downloadBtn');

    status.textContent = "Vacuuming & Compressing...";
    btn.disabled = true; // Prevent double-clicks during VACUUM

    try {
        // Trigger the download
        window.location.href = '/admin/download-db';

        status.textContent = "Download started!";
        status.style.color = "green";

        // Refresh stats after a short delay to reflect the latest state
        setTimeout(updateStats, 2000);
    } catch (error) {
        status.textContent = "Error: Backup failed.";
        status.style.color = "red";
    } finally {
        btn.disabled = false;
    }
});

// Initial load
updateStats();