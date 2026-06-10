# backend/cache/__init__.py
import cachetools
from datetime import datetime, timedelta
import json
import hashlib
from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)

class ModelCache:
    """Efficient caching system for models and predictions"""
    
    def __init__(self, maxsize=100, ttl_seconds=300):
        self.prediction_cache = cachetools.TTLCache(maxsize=maxsize, ttl=ttl_seconds)
        self.model_cache = {}
        self.stats_cache = cachetools.TTLCache(maxsize=50, ttl=60)
        
        # Add statistics tracking
        self.hits = 0
        self.misses = 0
    
    def get_prediction_cache_key(self, input_text: str, model_type: str) -> str:
        """Generate cache key for prediction"""
        content = f"{model_type}:{input_text}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def get_cached_prediction(self, cache_key: str) -> Optional[Any]:
        """Get cached prediction if exists"""
        result = self.prediction_cache.get(cache_key)
        if result:
            self.hits += 1
            logger.debug(f"L1 Cache HIT: {cache_key}")
        else:
            self.misses += 1
            logger.debug(f"L1 Cache MISS: {cache_key}")
        return result
    
    def cache_prediction(self, cache_key: str, result: Any):
        """Cache prediction result"""
        self.prediction_cache[cache_key] = result
        logger.debug(f"L1 Cache SET: {cache_key}")
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics including L1"""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        
        return {
            "l1": {
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(hit_rate, 2),
                "current_size": len(self.prediction_cache),
                "max_size": self.prediction_cache.maxsize,
                "ttl_seconds": self.prediction_cache.ttl
            },
            "prediction_cache_size": len(self.prediction_cache),
            "model_cache_size": len(self.model_cache),
            "stats_cache_size": len(self.stats_cache),
        }
    
    def clear_all(self):
        """Clear all caches"""
        self.prediction_cache.clear()
        self.model_cache.clear()
        self.stats_cache.clear()
        self.hits = 0
        self.misses = 0

# Global cache instance
cache_manager = ModelCache()