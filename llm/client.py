"""
LLM client for interacting with various language model APIs.
"""

import os
import json
import logging
import time
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import openai
from anthropic import Anthropic

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    LOCAL = "local"

@dataclass
class LLMConfig:
    """Configuration for LLM client."""
    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4000
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: int = 60
    max_retries: int = 3
    retry_delay: float = 1.0

@dataclass
class LLMResponse:
    """Response from LLM API."""
    content: str
    model: str
    usage: Optional[Dict[str, Any]] = None
    finish_reason: Optional[str] = None
    response_time: float = 0.0
    provider: Optional[str] = None

class LLMClient:
    """
    Universal LLM client supporting multiple providers.
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize provider-specific clients
        self._initialize_client()
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1.0  # Minimum seconds between requests
        
        # Usage tracking
        self.usage_stats = {
            'total_requests': 0,
            'total_tokens': 0,
            'total_cost': 0.0,
            'errors': 0,
            'average_response_time': 0.0
        }

    def _initialize_client(self):
        """Initialize the appropriate client based on provider."""
        if self.config.provider == LLMProvider.OPENAI:
            if not self.config.api_key:
                self.config.api_key = os.getenv('OPENAI_API_KEY')
            if not self.config.api_key:
                raise ValueError("OpenAI API key not provided")
            
            openai.api_key = self.config.api_key
            if self.config.base_url:
                openai.base_url = self.config.base_url
                
        elif self.config.provider == LLMProvider.ANTHROPIC:
            if not self.config.api_key:
                self.config.api_key = os.getenv('ANTHROPIC_API_KEY')
            if not self.config.api_key:
                raise ValueError("Anthropic API key not provided")
            
            self.anthropic_client = Anthropic(api_key=self.config.api_key)
            
        elif self.config.provider == LLMProvider.AZURE_OPENAI:
            if not self.config.api_key:
                self.config.api_key = os.getenv('AZURE_OPENAI_API_KEY')
            if not self.config.base_url:
                self.config.base_url = os.getenv('AZURE_OPENAI_ENDPOINT')
            if not self.config.api_key or not self.config.base_url:
                raise ValueError("Azure OpenAI credentials not provided")
            
            openai.api_key = self.config.api_key
            openai.base_url = self.config.base_url
            openai.api_type = "azure"
            
        self.logger.info(f"Initialized LLM client for {self.config.provider.value}")

    async def generate(self, prompt: str, system_prompt: Optional[str] = None, 
                      **kwargs) -> LLMResponse:
        """
        Generate response from LLM.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            **kwargs: Additional generation parameters
            
        Returns:
            LLMResponse: The generated response
        """
        start_time = time.time()
        
        try:
            # Rate limiting
            await self._rate_limit()
            
            # Merge kwargs with config
            generation_params = self._prepare_generation_params(**kwargs)
            
            # Generate response based on provider
            if self.config.provider == LLMProvider.OPENAI:
                response = await self._generate_openai(prompt, system_prompt, generation_params)
            elif self.config.provider == LLMProvider.ANTHROPIC:
                response = await self._generate_anthropic(prompt, system_prompt, generation_params)
            elif self.config.provider == LLMProvider.AZURE_OPENAI:
                response = await self._generate_azure_openai(prompt, system_prompt, generation_params)
            else:
                raise ValueError(f"Unsupported provider: {self.config.provider}")
            
            response.response_time = time.time() - start_time
            response.provider = self.config.provider.value
            
            # Update usage statistics
            self._update_usage_stats(response)
            
            self.logger.info(f"Generated response in {response.response_time:.2f}s")
            return response
            
        except Exception as e:
            self.usage_stats['errors'] += 1
            self.logger.error(f"Error generating response: {str(e)}")
            raise

    async def generate_with_retry(self, prompt: str, system_prompt: Optional[str] = None,
                                 **kwargs) -> LLMResponse:
        """
        Generate response with automatic retry logic.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            **kwargs: Additional generation parameters
            
        Returns:
            LLMResponse: The generated response
        """
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                return await self.generate(prompt, system_prompt, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    wait_time = self.config.retry_delay * (2 ** attempt)  # Exponential backoff
                    self.logger.warning(f"Attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}")
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.error(f"All {self.config.max_retries + 1} attempts failed")
        
        raise last_exception

    def generate_sync(self, prompt: str, system_prompt: Optional[str] = None,
                     **kwargs) -> LLMResponse:
        """
        Synchronous wrapper for generate method.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            **kwargs: Additional generation parameters
            
        Returns:
            LLMResponse: The generated response
        """
        return asyncio.run(self.generate(prompt, system_prompt, **kwargs))

    async def _rate_limit(self):
        """Implement rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            wait_time = self.min_request_interval - time_since_last
            await asyncio.sleep(wait_time)
        
        self.last_request_time = time.time()

    def _prepare_generation_params(self, **kwargs) -> Dict[str, Any]:
        """Prepare generation parameters by merging config and kwargs."""
        params = {
            'temperature': self.config.temperature,
            'max_tokens': self.config.max_tokens,
            'top_p': self.config.top_p,
            'frequency_penalty': self.config.frequency_penalty,
            'presence_penalty': self.config.presence_penalty,
        }
        
        # Override with provided kwargs
        params.update(kwargs)
        
        return params

    async def _generate_openai(self, prompt: str, system_prompt: Optional[str],
                              params: Dict[str, Any]) -> LLMResponse:
        """Generate response using OpenAI API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = await openai.ChatCompletion.acreate(
                model=self.config.model,
                messages=messages,
                temperature=params['temperature'],
                max_tokens=params['max_tokens'],
                top_p=params['top_p'],
                frequency_penalty=params['frequency_penalty'],
                presence_penalty=params['presence_penalty'],
                timeout=self.config.timeout
            )
            
            return LLMResponse(
                content=response.choices[0].message.content,
                model=response.model,
                usage=response.usage.to_dict() if response.usage else None,
                finish_reason=response.choices[0].finish_reason
            )
            
        except Exception as e:
            self.logger.error(f"OpenAI API error: {str(e)}")
            raise

    async def _generate_anthropic(self, prompt: str, system_prompt: Optional[str],
                                 params: Dict[str, Any]) -> LLMResponse:
        """Generate response using Anthropic API."""
        try:
            full_prompt = ""
            if system_prompt:
                full_prompt += f"System: {system_prompt}\n\n"
            full_prompt += f"Human: {prompt}\n\nAssistant:"
            
            response = await self.anthropic_client.completions.create(
                model=self.config.model,
                prompt=full_prompt,
                max_tokens_to_sample=params['max_tokens'],
                temperature=params['temperature'],
                top_p=params['top_p']
            )
            
            return LLMResponse(
                content=response.completion,
                model=self.config.model,
                usage={'completion_tokens': len(response.completion.split())},
                finish_reason='stop'
            )
            
        except Exception as e:
            self.logger.error(f"Anthropic API error: {str(e)}")
            raise

    async def _generate_azure_openai(self, prompt: str, system_prompt: Optional[str],
                                    params: Dict[str, Any]) -> LLMResponse:
        """Generate response using Azure OpenAI API."""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = await openai.ChatCompletion.acreate(
                engine=self.config.model,  # Azure uses engine instead of model
                messages=messages,
                temperature=params['temperature'],
                max_tokens=params['max_tokens'],
                top_p=params['top_p'],
                frequency_penalty=params['frequency_penalty'],
                presence_penalty=params['presence_penalty'],
                timeout=self.config.timeout
            )
            
            return LLMResponse(
                content=response.choices[0].message.content,
                model=response.model,
                usage=response.usage.to_dict() if response.usage else None,
                finish_reason=response.choices[0].finish_reason
            )
            
        except Exception as e:
            self.logger.error(f"Azure OpenAI API error: {str(e)}")
            raise

    def _update_usage_stats(self, response: LLMResponse):
        """Update usage statistics."""
        self.usage_stats['total_requests'] += 1
        
        if response.usage:
            tokens = response.usage.get('total_tokens', 0)
            self.usage_stats['total_tokens'] += tokens
            
            # Estimate cost (rough estimates)
            cost_per_token = self._get_cost_per_token()
            self.usage_stats['total_cost'] += tokens * cost_per_token
        
        # Update average response time
        current_avg = self.usage_stats['average_response_time']
        total_requests = self.usage_stats['total_requests']
        self.usage_stats['average_response_time'] = (
            (current_avg * (total_requests - 1) + response.response_time) / total_requests
        )

    def _get_cost_per_token(self) -> float:
        """Get estimated cost per token based on model."""
        cost_mapping = {
            'gpt-4': 0.00003,  # $0.03 per 1K tokens
            'gpt-3.5-turbo': 0.000002,  # $0.002 per 1K tokens
            'claude-v1': 0.000011,  # Rough estimate
            'claude-instant-v1': 0.0000016  # Rough estimate
        }
        
        return cost_mapping.get(self.config.model, 0.00001)

    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics."""
        return self.usage_stats.copy()

    def reset_usage_stats(self):
        """Reset usage statistics."""
        self.usage_stats = {
            'total_requests': 0,
            'total_tokens': 0,
            'total_cost': 0.0,
            'errors': 0,
            'average_response_time': 0.0
        }

    def validate_connection(self) -> bool:
        """Validate connection to LLM provider."""
        try:
            test_prompt = "Hello, this is a test. Please respond with 'Connection successful.'"
            response = self.generate_sync(test_prompt)
            return "successful" in response.content.lower()
        except Exception as e:
            self.logger.error(f"Connection validation failed: {str(e)}")
            return False

class LLMClientFactory:
    """Factory for creating LLM clients."""
    
    @staticmethod
    def create_client(provider: str, model: str, **kwargs) -> LLMClient:
        """
        Create LLM client based on provider.
        
        Args:
            provider: The LLM provider name
            model: The model name
            **kwargs: Additional configuration parameters
            
        Returns:
            LLMClient: Configured LLM client
        """
        provider_enum = LLMProvider(provider.lower())
        
        config = LLMConfig(
            provider=provider_enum,
            model=model,
            **kwargs
        )
        
        return LLMClient(config)

    @staticmethod
    def create_openai_client(model: str = "gpt-4", **kwargs) -> LLMClient:
        """Create OpenAI client with defaults."""
        return LLMClientFactory.create_client("openai", model, **kwargs)

    @staticmethod
    def create_anthropic_client(model: str = "claude-v1", **kwargs) -> LLMClient:
        """Create Anthropic client with defaults."""
        return LLMClientFactory.create_client("anthropic", model, **kwargs)

    @staticmethod
    def from_env() -> LLMClient:
        """Create client from environment variables."""
        provider = os.getenv('LLM_PROVIDER', 'openai')
        model = os.getenv('LLM_MODEL', 'gpt-4')
        
        config_params = {}
        if os.getenv('LLM_TEMPERATURE'):
            config_params['temperature'] = float(os.getenv('LLM_TEMPERATURE'))
        if os.getenv('LLM_MAX_TOKENS'):
            config_params['max_tokens'] = int(os.getenv('LLM_MAX_TOKENS'))
        
        return LLMClientFactory.create_client(provider, model, **config_params)
