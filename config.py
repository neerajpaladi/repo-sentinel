# config.py

import os
import sys
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    FEATHERLESS_API_KEY: str = "rc_195aa500d7780f00f8e6a1c161d45193d73a201a9c40f1a597b23c3f171591cb"
    FEATHERLESS_ENDPOINT: str = "https://api.featherless.ai/v1/chat/completions"
    MODEL_NAME: str = "moonshotai/Kimi-K2.5"
    WEASYPRINT_DLL_DIRECTORIES: str = r"C:\msys64\mingw64\bin"

    # Modern Pydantic v2 configuration
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        extra="ignore"
    )


settings = Settings()

# CRITICAL: WeasyPrint reads os.environ directly when loaded
if sys.platform == "win32" and settings.WEASYPRINT_DLL_DIRECTORIES:
    os.environ["WEASYPRINT_DLL_DIRECTORIES"] = settings.WEASYPRINT_DLL_DIRECTORIES