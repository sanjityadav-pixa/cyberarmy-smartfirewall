from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"status": "success", "message": "Welcome to Secure Corporate Internal Portal"}

@app.get("/api/user")
def get_user(id: str = "1"):
    return {"status": "success", "user_id": id, "role": "Employee"}

@app.get("/api/balance")
def get_balance():
    return {
        "status": "success",
        "account_id": "CORP-AEGIS-9921",
        "allocated_balance": 150000.00,
        "currency": "INR",
        "security_clearance": "L4_VALIDATED"
    }

if __name__ == "__main__":
    import uvicorn
    # Localhost par target server chalega
    uvicorn.run(app, host="127.0.0.1", port=9000)