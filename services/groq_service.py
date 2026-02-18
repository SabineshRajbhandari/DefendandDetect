import os
import time
import logging
from typing import Optional, Dict, Any
from groq import Groq, APIConnectionError, RateLimitError, APIStatusError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GroqService:
    """
    Singleton service for interacting with the GROQ API.
    Handles client initialization, secure key access, and error-resilient inference.
    """
    _instance = None
    _client = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GroqService, cls).__new__(cls)
        return cls._instance

    def _get_client(self) -> Optional[Groq]:
        """
        Lazy initialization of the GROQ client.
        """
        if self._client is None:
            api_key = Config.get_groq_api_key()
            if not api_key:
                logger.error("GROQ API Key not found.")
                return None
            
            try:
                self._client = Groq(api_key=api_key)
                logger.info("GROQ Client initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize GROQ client: {e}")
                return None
        return self._client

    @retry(
        retry=retry_if_exception_type((APIConnectionError, RateLimitError)),
        stop=stop_after_attempt(Config.MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=Config.RETRY_DELAY, max=10)
    )
    def execute_prompt(self, prompt: str, system_prompt: str = "You are a helpful cybersecurity assistant.", temperature: float = None) -> Dict[str, Any]:
        """
        Executes a prompt against the GROQ API with built-in retry logic.
        
        Args:
            prompt (str): The user input or specific query.
            system_prompt (str): Context setting for the AI.
            temperature (float): Overrides default temperature if provided.

        Returns:
            Dict[str, Any]: Structured response containing 'content', 'status', and 'error' (if any).
        """
        client = self._get_client()
        if not client:
            return {
                "status": "error",
                "content": None,
                "error": "API Key missing or client initialization failed."
            }

        try:
            # Use default temp from config if not specified
            temp = temperature if temperature is not None else Config.TEMPERATURE

            logger.info(f"Sending request to GROQ (Model: {Config.MODEL_NAME})")
            
            start_time = time.time()
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt,
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model=Config.MODEL_NAME,
                temperature=temp,
                max_tokens=Config.MAX_TOKENS,
            )
            elapsed_time = time.time() - start_time
            logger.info(f"GROQ Request completed in {elapsed_time:.2f}s")

            import re
            content = chat_completion.choices[0].message.content
            thought = ""
            
            # Extract thought if present
            thought_match = re.search(r"<thought>(.*?)</thought>", content, re.DOTALL)
            if thought_match:
                thought = thought_match.group(1).strip()
                content = re.sub(r"<thought>.*?</thought>", "", content, flags=re.DOTALL).strip()
            
            return {
                "status": "success",
                "content": content,
                "thought": thought,
                "model": chat_completion.model,
                "latency_ms": int(elapsed_time * 1000)
            }

        except RateLimitError as e:
            logger.warning(f"Rate limit hit: {e}")
            raise e # Let tenacity handle the retry
            
        except APIConnectionError as e:
            logger.warning(f"Connection error: {e}")
            raise e # Let tenacity handle the retry

        except APIStatusError as e:
            error_msg = f"API Error {e.status_code}: {e.message}"
            logger.error(error_msg)
            return {
                "status": "error",
                "content": None,
                "error": f"GROQ Service Unavailable: {e.message}"
            }
            
        except Exception as e:
            logger.error(f"Unexpected error during inference: {e}")
            return {
                "status": "error",
                "content": None,
                "error": f"An unexpected error occurred: {str(e)}"
            }

# Global instance for easy import
groq_service = GroqService()
