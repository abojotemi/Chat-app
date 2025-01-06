from fastapi import FastAPI
from contextlib import asynccontextmanager

from api.db.connect import init_db
from api.routes import user

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Server running")
    await init_db()
    yield
    print("Stopping Server")


app = FastAPI(lifespan=lifespan)


@app.get("/")
async def root():
    return {"message": "Hello, World!"}




app.include_router(user.router)