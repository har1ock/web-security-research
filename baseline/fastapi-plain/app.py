from fastapi import FastAPI, Response

app = FastAPI()

@app.post("/login")
def login(response: Response):
    # FastAPI не має вбудованого менеджера сесій «з коробки»,
    # тому просто ставимо звичайну куку для перевірки заголовків
    response.set_cookie(key="session", value="1")
    return {"status": "logged in"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5203)