import os

from celery import Celery

broker_url = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")

celery_app = Celery("mini_siem", broker=broker_url, backend=broker_url)
