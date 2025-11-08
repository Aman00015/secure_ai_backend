from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()



origins = [
    "https://secure-ai.netlify.app/",  
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


# Add CORS middleware for frontend




app.include_router(router)  # Connect to routes

@app.get("/")
def read_root():
    return {"message": "Security AI Scanner API is running!"}