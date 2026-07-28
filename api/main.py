from fastapi import FastAPI

app = FastAPI(title="ACT Backend")


@app.get("/")
def root():
    return {"message": "ACT Backend Running"}