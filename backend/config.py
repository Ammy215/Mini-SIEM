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

    # Context signals. Blank = not configured: the signal is skipped and the
    # alert's evidence says so. Checked at startup (detection/context.py).
    home_countries: str = ""          # two-letter codes, e.g. "US,CA" -> foreign_geo
    business_hours: str = ""          # e.g. "08:00-18:00" in business_timezone -> after_hours
    business_days: str = "mon-fri"
    business_timezone: str = "UTC"    # IANA name, e.g. "Europe/London"
    # Background country lookups for event source IPs (ipinfo, capped per tick).
    enable_geo_lookups: bool = True

    # Live syslog listener — for a local lab only, off by default
    # (ingest_listener/syslog_server.py). It won't start without an allowlist.
    enable_syslog_listener: bool = False
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 5514
    syslog_allowed_sources: str = ""  # comma-separated IPs / CIDR ranges
    syslog_rate_per_second: int = 200
    syslog_burst: int = 1000

    # Also enforced on the raw request body before it is read (middleware/body_size_limit.py).
    max_upload_bytes: int = 10 * 1024 * 1024
    max_ingest_body_bytes: int = 5 * 1024 * 1024


settings = Settings()
