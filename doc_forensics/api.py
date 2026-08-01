"""FastAPI local web endpoint for multipart image upload and forensic document scanning."""

import os
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from fastapi import FastAPI, UploadFile, File, HTTPException, status
    from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from doc_forensics.config import VeritasConfig, load_config
from doc_forensics.scanner import ForensicScanner
from doc_forensics import __version__


HTML_UI_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Veritas - Document ID Forensics</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent-color: #38bdf8;
            --text-color: #f8fafc;
            --text-dim: #94a3b8;
            --border-color: #334155;
            --authentic: #22c55e;
            --tampering: #ef4444;
            --inconclusive: #eab308;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 800px;
            width: 100%;
        }
        header {
            text-align: center;
            margin-bottom: 30px;
        }
        h1 { margin: 0 0 10px 0; color: var(--accent-color); font-size: 2.2rem; }
        p.subtitle { color: var(--text-dim); margin: 0; }
        .dropzone {
            border: 2px dashed var(--accent-color);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            background: rgba(56, 189, 248, 0.05);
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .dropzone:hover { background: rgba(56, 189, 248, 0.1); }
        .dropzone input { display: none; }
        .btn {
            background: var(--accent-color);
            color: #0f172a;
            border: none;
            padding: 12px 24px;
            font-size: 1rem;
            font-weight: bold;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 15px;
        }
        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            margin-top: 25px;
            border: 1px solid var(--border-color);
        }
        .badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9rem;
            text-transform: uppercase;
        }
        .badge.AUTHENTIC { background: var(--authentic); color: #000; }
        .badge.SUSPECTED_TAMPERING { background: var(--tampering); color: #fff; }
        .badge.INCONCLUSIVE { background: var(--inconclusive); color: #000; }
        .spinner {
            display: none;
            margin: 20px auto;
            border: 4px solid rgba(255,255,255,0.1);
            border-left-color: var(--accent-color);
            border-radius: 50%;
            width: 36px;
            height: 36px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { color: var(--text-dim); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Veritas DocumentID Forensics</h1>
            <p class="subtitle">Explainable & Deterministic Document Tampering Detection Engine</p>
        </header>

        <div class="card">
            <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
                <h3>📁 Drag & Drop Document Image or Click to Browse</h3>
                <p style="color:var(--text-dim);">Supported formats: JPG, JPEG, PNG, TIFF, BMP (Max 25MB)</p>
                <input type="file" id="fileInput" accept=".jpg,.jpeg,.png,.tiff,.bmp" onchange="handleFile(this.files[0])">
            </div>
            <div class="spinner" id="spinner"></div>
        </div>

        <div class="card" id="resultCard" style="display:none;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h2 style="margin:0;">Analysis Verdict</h2>
                <span class="badge" id="verdictBadge">AUTHENTIC</span>
            </div>
            <p id="riskScore" style="color:var(--text-dim); margin-top:5px;"></p>
            <p id="summaryText" style="white-space: pre-line; line-height: 1.5;"></p>

            <h3>Forensic Module Breakdown</h3>
            <table>
                <thead>
                    <tr><th>Module</th><th>Status</th><th>Score</th><th>Evidence</th></tr>
                </thead>
                <tbody id="breakdownTable"></tbody>
            </table>
        </div>
    </div>

    <script>
        const dropzone = document.getElementById('dropzone');
        dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.style.borderColor = '#22c55e'; });
        dropzone.addEventListener('dragleave', () => { dropzone.style.borderColor = 'var(--accent-color)'; });
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--accent-color)';
            if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
        });

        async function handleFile(file) {
            if (!file) return;
            document.getElementById('spinner').style.display = 'block';
            document.getElementById('resultCard').style.display = 'none';

            const formData = new FormData();
            formData.append('file', file);

            try {
                const resp = await fetch('/scan', { method: 'POST', body: formData });
                const data = await resp.json();
                document.getElementById('spinner').style.display = 'none';

                if (!resp.ok) {
                    alert('Upload Error: ' + (data.detail || 'Failed to analyze file'));
                    return;
                }

                document.getElementById('resultCard').style.display = 'block';
                const badge = document.getElementById('verdictBadge');
                badge.textContent = data.verdict;
                badge.className = 'badge ' + data.verdict;

                document.getElementById('riskScore').textContent = 'Overall Risk Score: ' + (data.overall_risk_score * 100).toFixed(1) + '%';
                document.getElementById('summaryText').textContent = data.summary;

                const tbody = document.getElementById('breakdownTable');
                tbody.innerHTML = '';
                for (const [mod, check] of Object.entries(data.checks)) {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td style="font-weight:bold; color:var(--accent-color);">${mod}</td>
                        <td><span class="badge ${check.status}">${check.status}</span></td>
                        <td>${(check.score * 100).toFixed(1)}%</td>
                        <td style="color:var(--text-dim); font-size:0.9rem;">${check.explanation}</td>
                    `;
                    tbody.appendChild(tr);
                }
            } catch (err) {
                document.getElementById('spinner').style.display = 'none';
                alert('Connection Error: ' + err.message);
            }
        }
    </script>
</body>
</html>
"""


def create_app(config: Optional[VeritasConfig] = None) -> Any:
    """
    Create and configure local FastAPI application for Veritas doc-forensics API.
    """
    if not HAS_FASTAPI:
        raise RuntimeError("FastAPI library is not installed. Install with 'pip install fastapi uvicorn'.")

    cfg = config or load_config()
    app = FastAPI(
        title="Veritas Doc-Forensics API",
        description="Local web upload endpoint for document ID tampering detection",
        version=__version__
    )

    @app.get("/", response_class=HTMLResponse)
    def root_ui():
        """Render interactive web upload UI for browser users."""
        return HTML_UI_PAGE

    @app.get("/health")
    def health_check():
        return {"status": "ok", "veritas_version": __version__}

    @app.post("/scan")
    async def scan_upload(file: UploadFile = File(...)):
        """
        Accept multipart file upload, validate format & size, execute forensic scanner,
        and delete temporary file immediately afterward for privacy sensitivity.
        """
        if not file.filename:
            raise HTTPException(status_code=400, detail="Uploaded file missing filename.")

        ext = Path(file.filename).suffix.lower()
        allowed_exts = [e.lower() for e in cfg.allowed_extensions]
        if ext not in allowed_exts:
            allowed_str = ", ".join(allowed_exts)
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file format '{ext}'. Allowed formats: {allowed_str}"
            )

        # Read content bytes into memory for size check
        content = await file.read()
        file_size_mb = len(content) / (1024.0 * 1024.0)
        if file_size_mb > cfg.max_file_size_mb:
            raise HTTPException(
                status_code=400,
                detail=f"File size ({round(file_size_mb, 2)} MB) exceeds maximum allowed limit of {cfg.max_file_size_mb} MB"
            )

        # Create temporary file in OS temp directory
        temp_fd, temp_path_str = tempfile.mkstemp(suffix=ext, prefix="veritas_upload_")
        temp_path = Path(temp_path_str)

        try:
            with os.fdopen(temp_fd, "wb") as f:
                f.write(content)

            # Run scanner pipeline
            scanner = ForensicScanner(config=cfg)
            report = scanner.scan(temp_path)
            
            # Replace temporary path in report response with original uploaded filename
            report_dict = report.to_dict()
            report_dict["image_path"] = file.filename

            return JSONResponse(content=report_dict)
        except ValueError as val_err:
            raise HTTPException(status_code=400, detail=str(val_err))
        except Exception as err:
            raise HTTPException(status_code=500, detail=f"Forensic scan error: {str(err)}")
        finally:
            # Guarantee temp file auto-cleanup for privacy protection
            if cfg.auto_delete_temp_files and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass

    return app
