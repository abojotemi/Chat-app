from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    POSTGRES_URL: str
    PORT: int
    JWT_SECRET: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    ALGORITHM: str
    model_config: SettingsConfigDict = SettingsConfigDict(
        env_file=".env", extra="ignore"
    )


Config = Settings()
