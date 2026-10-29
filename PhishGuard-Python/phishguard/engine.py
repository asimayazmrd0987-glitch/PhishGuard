"""Risk scoring and public scanning facade."""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from .algorithms import merge_sort
from .analyzers import MessageAnalyzer, UrlAnalysis, UrlAnalyzer
from .detection_data import DetectionData, RiskConfig
from .ds import CustomSet
from .types import AnalysisResult, Indicator, IndicatorCategory, InputType, RiskLevel
from .url_parser import looks_like_url


class RiskEngine:
    SAFETY_RECOMMENDATIONS = (
        (
            'phrase_self_harm',
            'This message mentions self-harm or suicide. If you are thinking about harming yourself, '
            'contact local emergency services or a crisis line now and reach out to someone you trust. '
            'If someone sent this to you, treat it as abusive and seek support.',
        ),
        (
            'phrase_threat',
            'This message contains a direct threat of violence. Do not reply, do not meet the sender, '
            'and do not share your location. Save the message as evidence, block the sender, and contact '
            'local emergency services if you believe the threat is immediate.',
        ),
        (
            'phrase_extortion',
            'This message uses blackmail or extortion pressure. Do not pay, do not send images or '
            'verification codes, and keep the evidence. Save screenshots, block the sender, and report it '
            'to the platform or local authorities.',
        ),
        (
            'phrase_harassment',
            'This message contains abusive or degrading language. Do not engage. Save evidence if you '
            'need it, block and report the sender, and tell someone you trust.',
        ),
    )

    def __init__(self, config: RiskConfig):
        self.config = config

    def evaluate(self, raw: list[Indicator]) -> AnalysisResult:
        """De-duplicate, rank, cap and score a list of indicators.

        Indicator objects supplied by callers are never mutated; applying the
        keyword cap creates a capped copy for the retained result.
        """
        seen = CustomSet[str]()
        unique: list[Indicator] = []
        for indicator in raw:
            if seen.insert(indicator.id):
                unique.append(indicator)
        merge_sort(unique, lambda a, b: a.weight > b.weight)  # stable descending order

        budget = self.config.value('cap.keyword')
        total = 0
        retained: list[Indicator] = []
        for indicator in unique:
            candidate = indicator
            if candidate.category == IndicatorCategory.KEYWORD:
                if budget <= 0:
                    continue
                if candidate.weight > budget:
                    candidate = replace(candidate, weight=budget)
                budget -= candidate.weight
            if candidate.weight <= 0:
                continue
            total += candidate.weight
            retained.append(candidate)

        score = min(100, total)
        level = self.config.level_for(score)
        return AnalysisResult(
            score=score,
            level=level,
            indicators=retained,
            recommendation=self.recommendation_for(level, retained),
        )

    @classmethod
    def recommendation_for(
        cls,
        level: RiskLevel,
        indicators: Optional[list[Indicator]] = None,
    ) -> str:
        present = {indicator.id for indicator in indicators or ()}
        safety_advice = [
            message
            for indicator_id, message in cls.SAFETY_RECOMMENDATIONS
            if indicator_id in present
        ]
        if safety_advice:
            return '\n\n'.join(safety_advice)
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
        if parsed.valid and parsed.host_is_ip:
            result.findings.ips.append(parsed.host)
        if url_analysis.impersonation and (
            result.findings.impersonation is None
            or url_analysis.impersonation.distance < result.findings.impersonation.distance
        ):
            result.findings.impersonation = url_analysis.impersonation

    def _finish(self, result: AnalysisResult) -> AnalysisResult:
        scored = self.engine.evaluate(result.indicators)
        result.score, result.level = scored.score, scored.level
        result.indicators, result.recommendation = scored.indicators, scored.recommendation
        for indicator in result.indicators:
            if indicator.category == IndicatorCategory.KEYWORD:
                result.findings.keywords.append(indicator.detail)
            if indicator.id == 'known_threat':
                result.findings.threat_domains.append(indicator.detail)
        return result

    def scan_url(self, url: str) -> AnalysisResult:
        result = AnalysisResult(type=InputType.URL, input=url)
        analysis = self.urls.analyze(url)
        self._collect_findings(analysis, result)
        result.indicators = analysis.indicators
        return self._finish(result)

    def scan_message(self, text: str, input_type: InputType = InputType.MESSAGE) -> AnalysisResult:
        if input_type == InputType.URL:
            return self.scan_url(text)
        result = AnalysisResult(type=input_type, input=text)
        analysis = self.messages.analyze(text)
        for url in analysis.urls:
            self._collect_findings(url, result)
        result.indicators = analysis.indicators
        return self._finish(result)

    def scan_email(self, text: str) -> AnalysisResult:
        return self.scan_message(text, InputType.EMAIL)

    def scan_auto(self, text: str) -> AnalysisResult:
        """Scan a URL-looking single line as a URL, otherwise as a message."""
        return self.scan_url(text) if looks_like_url(text.strip()) else self.scan_message(text)


__all__ = ['RiskEngine', 'ScanService']
