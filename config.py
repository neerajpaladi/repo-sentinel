import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    FEATHERLESS_API_KEY: str = os.getenv("FEATHERLESS_API_KEY", "rc_195aa500d7780f00f8e6a1c161d45193d73a201a9c40f1a597b23c3f171591cb")
    FEATHERLESS_ENDPOINT: str = "https://api.featherless.ai/v1/chat/completions"
    MODEL_NAME: str = "moonshotai/Kimi-K2.5"

    class Config:
        env_file = ".env"

settings = Settings()