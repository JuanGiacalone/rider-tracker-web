const handleAuthError = () => {
    console.warn("Authentication required or token expired. Redirecting to home...");
    localStorage.removeItem('adminToken');
    localStorage.removeItem('username');
    document.cookie = "authToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC; SameSite=Strict";
    window.location.href = '/';
};

const updateStats = async () => {
    try {
        const token = localStorage.getItem('adminToken');
        const response = await fetch('/admin/db-stats', {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401) {
            handleAuthError();
            return;
        }

        const data = await response.json();

        // Format the date nicely (e.g., Oct 24, 2023, 2:30 PM)
        const date = new Date(data.lastModified);
        document.getElementById('lastUpdated').textContent = date.toLocaleString();
        document.getElementById('dbSize').textContent = data.size;
    } catch (err) {
        document.getElementById('lastUpdated').textContent = "Error fetching stats";
    }
};

// Initial load and event listeners setup
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('downloadBtn').addEventListener('click', async () => {
        const status = document.getElementById('statusMessage');
        const btn = document.getElementById('downloadBtn');

        status.textContent = "Vacuuming & Compressing...";
        btn.disabled = true; // Prevent double-clicks during VACUUM

        try {
            const token = localStorage.getItem('adminToken');
            // Trigger the download with token in query param for reliability
            window.location.href = `/admin/download-db?token=${token}`;

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

    let allStores = [];

    const fetchTenants = async () => {
        try {
            const token = localStorage.getItem('adminToken');
            const response = await fetch('/api/admin/tenants', {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (response.status === 401) {
                handleAuthError();
                return;
            }

            const tenants = await response.json();

            const tenantSelects = [document.getElementById('tenantSelect'), document.getElementById('riderTenantSelect')];
            tenantSelects.forEach(sel => {
                const currentValue = sel.value;
                sel.innerHTML = '<option value="">Select Tenant</option>';
                tenants.forEach(t => {
                    const opt = document.createElement('option');
                    opt.value = t.id;
                    opt.textContent = t.name;
                    sel.appendChild(opt);
                });
                sel.value = currentValue;
            });
        } catch (err) {
            console.error("Error fetching tenants:", err);
        }
    };

    const fetchStores = async () => {
        try {
            const token = localStorage.getItem('adminToken');
            const response = await fetch('/api/admin/stores', {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (response.status === 401) {
                handleAuthError();
                return;
            }

            allStores = await response.json();
        } catch (err) {
            console.error("Error fetching stores:", err);
        }
    };

    document.getElementById('riderTenantSelect').addEventListener('change', (e) => {
        const tenantId = parseInt(e.target.value);
        const storeSelect = document.getElementById('riderStoreSelect');

        storeSelect.innerHTML = '<option value="">Select Store</option>';
        if (!tenantId) {
            storeSelect.disabled = true;
            return;
        }

        const filtered = allStores.filter(s => s.tenant_id === tenantId);
        filtered.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.textContent = s.name;
            storeSelect.appendChild(opt);
        });
        storeSelect.disabled = false;
    });

    document.getElementById('tenantForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const status = document.getElementById('tenantStatus');
        const name = document.getElementById('tenantName').value;
        const endpoint = document.getElementById('tenantEndpoint').value;
        const icon_url = document.getElementById('tenantIconUrl').value;
        const active = document.getElementById('tenantActive').checked;
        const token = localStorage.getItem('adminToken');

        status.textContent = "Creating...";
        status.style.color = "black";

        try {
            const response = await fetch('/api/admin/tenants', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ name, endpoint, icon_url, active })
            });

            if (response.status === 401) {
                handleAuthError();
                return;
            }

            const data = await response.json();
            if (data.success) {
                status.textContent = "Tenant created!";
                status.style.color = "green";
                document.getElementById('tenantForm').reset();
                fetchTenants();
            } else {
                status.textContent = data.error || "Failed to create tenant";
                status.style.color = "red";
            }
        } catch (err) {
            status.textContent = "Connection error";
            status.style.color = "red";
        }
    });

    document.getElementById('storeForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const status = document.getElementById('storeStatus');
        const tenantId = document.getElementById('tenantSelect').value;
        const name = document.getElementById('storeName').value;
        const lat = document.getElementById('storeLat').value;
        const lng = document.getElementById('storeLng').value;
        const active = document.getElementById('storeActive').checked;
        const token = localStorage.getItem('adminToken');

        status.textContent = "Adding...";
        status.style.color = "black";

        try {
            const response = await fetch('/api/stores', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    tenantId: parseInt(tenantId),
                    name,
                    lat: lat ? parseFloat(lat) : null,
                    lng: lng ? parseFloat(lng) : null,
                    active
                })
            });

            if (response.status === 401) {
                handleAuthError();
                return;
            }

            const data = await response.json();
            if (data.success) {
                status.textContent = "Store added!";
                status.style.color = "green";
                document.getElementById('storeForm').reset();
                fetchStores(); // Refresh global store list
            } else {
                status.textContent = data.error || "Failed to add store";
                status.style.color = "red";
            }
        } catch (err) {
            status.textContent = "Connection error";
            status.style.color = "red";
        }
    });

    document.getElementById('riderForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const status = document.getElementById('riderStatus');
        const tenantId = document.getElementById('riderTenantSelect').value;
        const storeId = document.getElementById('riderStoreSelect').value;
        const username = document.getElementById('riderUsername').value;
        const password = document.getElementById('riderPassword').value;
        const isAdmin = document.getElementById('riderIsAdmin').checked;
        const token = localStorage.getItem('adminToken');

        status.textContent = "Adding...";
        status.style.color = "black";

        try {
            const response = await fetch('/api/riders', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    tenantId: parseInt(tenantId),
                    storeId: parseInt(storeId),
                    username,
                    password,
                    isAdmin
                })
            });

            if (response.status === 401) {
                handleAuthError();
                return;
            }

            const data = await response.json();
            if (data.success) {
                status.textContent = "Rider/Admin added!";
                status.style.color = "green";
                document.getElementById('riderForm').reset();
                document.getElementById('riderStoreSelect').disabled = true;
            } else {
                status.textContent = data.error || "Failed to add user";
                status.style.color = "red";
            }
        } catch (err) {
            status.textContent = "Connection error";
            status.style.color = "red";
        }
    });

    // Initial load
    updateStats();
    fetchTenants();
    fetchStores();
});