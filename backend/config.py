from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    secret_key: str = "change_me_to_a_long_random_string"
    jwt_access_ttl_min: int = 30
    jwt_refresh_ttl_days: int = 7
    frontend_origin: str = "http://localhost:5173"

    database_url: str

    admin_email: str = "admin@example.com"
    admin_password: str = "change_me_strong_password"

    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    ipinfo_token: str = ""
    virustotal_api_key: str = ""
    nvd_api_key: str = ""

    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"

    enable_attack_lab: bool = False

    detection_interval_seconds: int = 60

    # Also enforced on the raw request body before it is read (middleware/body_size_limit.py).
    max_upload_bytes: int = 10 * 1024 * 1024
    max_ingest_body_bytes: int = 5 * 1024 * 1024


settings = Settings()
