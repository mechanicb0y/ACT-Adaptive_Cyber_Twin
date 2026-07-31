from fastapi import FastAPI

app = FastAPI(
    title="ACT Backend",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "project": "ACT",
        "status": "running"
    }