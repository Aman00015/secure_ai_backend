Render deployment guide for this FastAPI backend

Overview
- This project exposes a FastAPI app in `main.py` as `app`.
- We recommend using Gunicorn with the Uvicorn worker on Render.

Files added
- `Procfile`: start command used by Render

Quick steps to deploy on Render (web service)
1. Create a new Web Service on Render (https://dashboard.render.com/new)
   - Connect your repository (GitHub/GitLab)
   - Select the branch you want to deploy
2. Service settings
   - Environment: Python 3 (Render will detect from runtime; you can set a specific Python version in Render if needed)
   - Build Command: pip install -r requirements.txt
   - Start Command: leave empty if using `Procfile` (Render will use it), or set explicitly:
     gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT
   - Instance Type: choose based on traffic; Starter is fine for testing
3. Environment variables / secrets
   - If you use any API keys (e.g., Gemini / Google generative AI), add them under Environment -> Environment Variables in Render
   - Example: GEMINI_API_KEY
4. Health check
   - The app exposes `/health` and `/phishing/health` endpoints (see `routes.py`). Use `/health` to confirm deployment.
5. Static files / uploads
   - This project is a backend API. If you need persistent storage, attach a managed database or an S3-compatible bucket.

Local testing
- Create and activate a virtual env

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
# Run with uvicorn for local dev
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
# Or run the production-like server
gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000
```

Notes and troubleshooting
- Ensure `main.py` exposes `app` (this repo does). Render's start command expects `module:app`.
- If build fails due to private packages, add credentials as env vars or vendor those packages.
- If you need a specific Python version, set it in Render service settings or add a `runtime.txt` (optional).

Optional: `render.yaml`
- If you prefer GitOps for Render, create a `render.yaml` describing the service and push to repo. See Render docs for schema.

That's all — once the service is created Render will build, install `requirements.txt`, and start using the `Procfile` command.
