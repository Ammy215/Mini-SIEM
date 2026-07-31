from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Mini SIEM"
    environment: str = "development"
    cors_origins: list[str] = ["http://localhost:3000"]


settings = Settings()
