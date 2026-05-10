# Prompt Injection Firewall — Windows PowerShell Setup
$ErrorActionPreference = "Stop"

Write-Host "=== Prompt Injection Firewall — Setup ===" -ForegroundColor Cyan

# 1. Create virtual environment
python -m venv venv

# 2. Activate venv
.\venv\Scripts\Activate.ps1

# 3. Upgrade pip
pip install --upgrade pip

# 4. Install dependencies
pip install -r requirements.txt

# 5. Download spaCy English model
python -m spacy download en_core_web_sm

# 6. Copy .env if not exists
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ""
    Write-Host "⚠️  .env file created. Add your GROQ_API_KEY to .env before running." -ForegroundColor Yellow
    Write-Host "   Get your FREE key at: https://console.groq.com" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Add GROQ_API_KEY to .env"
Write-Host "  2. .\venv\Scripts\Activate.ps1"
Write-Host "  3. uvicorn app.main:app --reload            # start the API"
Write-Host "  4. streamlit run dashboard/app.py           # start dashboard"
Write-Host "  5. pytest tests/ -v                         # run tests"
