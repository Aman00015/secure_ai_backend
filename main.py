from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Use absolute import instead of relative import
try:
    from routes import router  # Remove the dot - use absolute import
except ImportError as e:
    print(f"Import error: {e}")
    # Fallback: create a basic router
    from fastapi import APIRouter
    router = APIRouter()
    
    @router.get("/test")
    def test_route():
        return {"message": "Routes module not found - check imports"}

app = FastAPI()

# Add CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
    expose_headers=['*'],
    max_age=600,
)

app.include_router(router)  # Connect to routes

@app.get("/")
def read_root():
    return {"message": "Security AI Scanner API is running!"}