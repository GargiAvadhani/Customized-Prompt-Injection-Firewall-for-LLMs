#!/bin/bash
set -e

echo "=== Prompt Injection Firewall — Setup ==="

# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Upgrade pip
pip install --upgrade pip

# 3. Install dependencies
pip install -r requirements.txt

# 4. Download spaCy English model
python -m spacy download en_core_web_sm

# 5. Copy .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo "⚠️  .env file created. Add your GROQ_API_KEY to .env before running."
    echo "   Get your FREE key at: https://console.groq.com"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Add GROQ_API_KEY to .env"
echo "  2. source venv/bin/activate"
echo "  3. uvicorn app.main:app --reload            # start the API"
echo "  4. streamlit run dashboard/app.py           # start dashboard"
echo "  5. pytest tests/ -v                         # run tests"
