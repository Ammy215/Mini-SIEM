from pydantic import BaseModel


class LoginAttemptIn(BaseModel):
    username: str
    password: str


class LoginAttemptResult(BaseModel):
    success: bool
    message: str


class SearchResult(BaseModel):
    query: str
    results: list[str]
