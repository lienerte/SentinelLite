# core/__init__.py
"""
SentinelLite Core Analytics and Routing Engine Subsystem.
Exposes automatic log classification, parsing routing factories, 
and the plugin execution engine.
"""

from .log_classifier import LogClassifier
from .parser_factory import ParserFactory
from .analysis_engine import AnalysisEngine
from .ai_analyzer import AIIntegrationLayer

# Define what gets imported when someone uses "from core import *"
__all__ = [
    "LogClassifier",
    "ParserFactory",
    "AnalysisEngine",
    "AIIntegrationLayer"
]