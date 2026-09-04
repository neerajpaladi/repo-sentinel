import httpx
from typing import List, Dict, Any, Optional
from config import settings

class FeatherlessClient:
    def __init__(self, api_key: str = settings.FEATHERLESS_API_KEY, endpoint: str = settings.FEATHERLESS_ENDPOINT):
        self.endpoint = endpoint
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    async def generate(
        self, 
        messages: List[Dict[str, str]], 
        temperature: float = 0.7,
        max_tokens: Optional[int] = 4096
    ) -> str:
        """Executes completions against Featherless AI's OpenAI-compatible endpoint."""
        payload: Dict[str, Any] = {
            "model": settings.MODEL_NAME,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(self.endpoint, headers=self.headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

featherless_client = FeatherlessClient()