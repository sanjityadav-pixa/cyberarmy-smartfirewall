from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"status": "success", "message": "Welcome to Secure Corporate Internal Portal"}

@app.get("/api/user")
def get_user(id: str = "1"):
    return {"status": "success", "user_id": id, "role": "Employee"}

if __name__ == "__main__":
    import uvicorn
    # Localhost par target server chalega
    uvicorn.run(app, host="127.0.0.1", port=9000)