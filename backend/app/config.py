from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    appname: str = "SentryNode"
    environment: str = "development"
    loglevel: str = "INFO"

    jwtsecret: str = "change-me"
    abuseipdbapikey: str = "change-me"
    discordwebhookurl: Optional[str] = None

    redishost: str = "localhost"
    redisport: int = 6379
    redisdb: int = 0
    redisttlseconds: int = 3600

    demomode: bool = False
    corsorigins: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Compatibility alias for existing imports
getsettings = get_settings
