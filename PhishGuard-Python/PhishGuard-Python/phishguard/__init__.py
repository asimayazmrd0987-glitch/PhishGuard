"""PhishGuard: explainable heuristic phishing and scam-message analyser."""
from .detection_data import DetectionData, RiskConfig
from .engine import ScanService, RiskEngine
from .types import AnalysisResult, InputType, RiskLevel, Indicator

__version__ = '1.0.0-python'
__all__ = ['DetectionData', 'RiskConfig', 'ScanService', 'RiskEngine', 'AnalysisResult', 'InputType', 'RiskLevel', 'Indicator']
