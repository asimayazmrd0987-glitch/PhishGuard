"""Risk scoring and public scanning facade."""
from __future__ import annotations
from .analyzers import MessageAnalyzer, UrlAnalyzer, UrlAnalysis
from .algorithms import merge_sort
from .detection_data import DetectionData, RiskConfig
from .ds import CustomSet
from .types import AnalysisResult, Indicator, IndicatorCategory, InputType, RiskLevel

class RiskEngine:
    def __init__(self, config: RiskConfig): self.config = config

    def evaluate(self, raw: list[Indicator]) -> AnalysisResult:
        seen = CustomSet[str]()
        unique = []
        for indicator in raw:
            if seen.insert(indicator.id): unique.append(indicator)
        merge_sort(unique, lambda a, b: a.weight > b.weight)  # preserve the C++ edition's stable merge sort
        budget = self.config.value('cap.keyword')
        total = 0
        retained: list[Indicator] = []
        for indicator in unique:
            if indicator.category == IndicatorCategory.KEYWORD:
                if budget <= 0: continue
                if indicator.weight > budget: indicator.weight = budget
                budget -= indicator.weight
            if indicator.weight <= 0: continue
            total += indicator.weight
            retained.append(indicator)
        score = min(100, total)
        level = self.config.level_for(score)
        return AnalysisResult(score=score, level=level, indicators=retained, recommendation=self.recommendation_for(level))

    @staticmethod
    def recommendation_for(level: RiskLevel) -> str:
        if level == RiskLevel.LOW:
            return 'Probably safe based on the checks we ran, but stay careful. If you did not expect this, confirm it through an official website or app.'
        if level == RiskLevel.MEDIUM:
            return 'Some suspicious signs were found. Do not enter passwords or payment details until you have checked through the official website or app.'
        if level == RiskLevel.HIGH:
            return 'Several suspicious signs were found. Do not click the link or share personal information. Contact the company using the phone number on its official website.'
        return 'DO NOT ENTER YOUR PASSWORD.\nDO NOT PROVIDE OTP OR PAYMENT INFORMATION.\nVERIFY THE SENDER THROUGH AN OFFICIAL SOURCE.'

class ScanService:
    def __init__(self, data: DetectionData):
        self.data = data
        self.urls = UrlAnalyzer(data)
        self.messages = MessageAnalyzer(data)
        self.engine = RiskEngine(data.config)

    @staticmethod
    def _collect_findings(url_analysis: UrlAnalysis, result: AnalysisResult) -> None:
        parsed = url_analysis.parsed
        result.findings.urls.append(parsed.original)
        result.findings.domains.append(parsed.host if parsed.valid else '')
        if parsed.valid and parsed.host_is_ip: result.findings.ips.append(parsed.host)
        if url_analysis.impersonation and (result.findings.impersonation is None or url_analysis.impersonation.distance < result.findings.impersonation.distance):
            result.findings.impersonation = url_analysis.impersonation

    def _finish(self, result: AnalysisResult) -> AnalysisResult:
        scored = self.engine.evaluate(result.indicators)
        result.score, result.level = scored.score, scored.level
        result.indicators, result.recommendation = scored.indicators, scored.recommendation
        for indicator in result.indicators:
            if indicator.category == IndicatorCategory.KEYWORD: result.findings.keywords.append(indicator.detail)
            if indicator.id == 'known_threat': result.findings.threat_domains.append(indicator.detail)
        return result

    def scan_url(self, url: str) -> AnalysisResult:
        result = AnalysisResult(type=InputType.URL, input=url)
        analysis = self.urls.analyze(url)
        self._collect_findings(analysis, result)
        result.indicators = analysis.indicators
        return self._finish(result)

    def scan_message(self, text: str, input_type: InputType = InputType.MESSAGE) -> AnalysisResult:
        result = AnalysisResult(type=input_type, input=text)
        analysis = self.messages.analyze(text)
        for url in analysis.urls: self._collect_findings(url, result)
        result.indicators = analysis.indicators
        return self._finish(result)
