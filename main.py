from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ✅ Allowed frontend origins (no trailing slash!)
origins = [
    "https://secure-ai.netlify.app",
    "http://localhost:3000",  # optional: for local testing
    "http://localhost:5173",  # optional: for local testing (Vite)
]

# ✅ Add CORS middleware BEFORE including routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Import routes (after CORS)
try:
    from routes import router
except ImportError as e:
    print(f"Import error: {e}")
    from fastapi import APIRouter
    router = APIRouter()

    @router.get("/test")
    def test_route():
        return {"message": "Routes module not found - check imports"}

app.include_router(router)

@app.get("/")
def read_root():
    return {"message": "Security AI Scanner API is running!"}
