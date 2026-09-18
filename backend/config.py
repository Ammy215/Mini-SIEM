from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Both are public: they sit in this repository's .env.example.
PLACEHOLDER_SECRET_KEY = "change_me_to_a_long_random_string"
PLACEHOLDER_ADMIN_PASSWORD = "change_me_strong_password"
# RFC 7518 §3.2: an HS256 key must be at least as long as the hash output.
MIN_SECRET_KEY_BYTES = 32


class Settings(BaseSettings):
    # hide_input_in_errors: a settings validation error otherwise prints the
    # whole input dict — DATABASE_URL and every API key — into the process
    # log, which on a host like Render is readable in the dashboard.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    app_env: str = "development"
    secret_key: str = PLACEHOLDER_SECRET_KEY
    jwt_access_ttl_min: int = 30
    jwt_refresh_ttl_days: int = 7
    frontend_origin: str = "http://localhost:5173"

    database_url: str

    admin_email: str = "admin@example.com"
    admin_password: str = PLACEHOLDER_ADMIN_PASSWORD

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

    @model_validator(mode="after")
    def _refuse_a_forgeable_secret_in_production(self):
        # SECRET_KEY signs every access and refresh token. Left at the default,
        # production would sign them with a string anyone can read in this repo,
        # and anyone could mint an admin token. Development keeps the default so
        # a fresh checkout still runs.
        if self.app_env != "production":
            return self
        if self.secret_key == PLACEHOLDER_SECRET_KEY:
            raise ValueError(
                "SECRET_KEY is still the placeholder from .env.example; set a long random value "
                'in production (e.g. python -c "import secrets; print(secrets.token_urlsafe(64))")'
            )
        if len(self.secret_key.encode()) < MIN_SECRET_KEY_BYTES:
            raise ValueError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_BYTES} bytes in production "
                f"(it is {len(self.secret_key.encode())})"
            )
        return self


settings = Settings()
