document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const btn = document.querySelector('.scan-btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');
    const resultsDiv = document.getElementById('results');
    const statusDiv = document.getElementById('status');
    const findingsDiv = document.getElementById('findings');
    
    // Show loading state
    btn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline';
    
    const formData = {
        url: document.getElementById('url').value,
        parameter: document.getElementById('parameter').value,
        method: document.getElementById('method').value
    };
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        // Display results
        resultsDiv.style.display = 'block';
        
        if (data.vulnerable) {
            statusDiv.className = 'status vulnerable';
            statusDiv.innerHTML = `⚠️ VULNERABLE: SQL Injection detected!`;
            
            findingsDiv.innerHTML = data.findings.map(f => `
                <div class="finding-card">
                    <h4>${f.type} (${f.severity})</h4>
                    <p><strong>Payload:</strong> <code>${f.payload}</code></p>
                    <p><strong>Evidence:</strong> ${f.evidence}</p>
                </div>
            `).join('');
        } else {
            statusDiv.className = 'status safe';
            statusDiv.innerHTML = `✅ No SQL injection vulnerabilities detected`;
            findingsDiv.innerHTML = '<p>The target appears to be safe from basic SQL injection attacks.</p>';
        }
        
        // Show download button if report available
        if (data.scan_time) {
            document.getElementById('download-section').style.display = 'block';
        }
        
    } catch (error) {
        statusDiv.className = 'status vulnerable';
        statusDiv.innerHTML = `❌ Error: ${error.message}`;
    } finally {
        btn.disabled = false;
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
});
