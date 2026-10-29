"""Regression tests for personal-safety language (threats, self-harm, extortion, abuse)."""
from __future__ import annotations

import unittest
from pathlib import Path

from phishguard.detection_data import DetectionData
from phishguard.engine import ScanService
from phishguard.types import IndicatorCategory, RiskLevel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data'


def data() -> DetectionData:
    return DetectionData.load_from_directory(DATA)


def indicator_ids(result) -> set[str]:
    return {indicator.id for indicator in result.indicators}


class SafetyDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = data()
        self.service = ScanService(self.data)

    def test_direct_violent_threats_are_high_risk(self):
        samples = (
            'I will kill you',
            "I'll kill you",
            'I am going to kill you',
            'I will murder you',
            'I will hurt you',
            'I will kill him',
            'I know where you live',
            'You are dead',
            'KILL YOU!!! 😡',
            'I will kill you.\nDo you understand?',
        )
        for text in samples:
            with self.subTest(text=text):
                result = self.service.scan_message(text)
                self.assertGreaterEqual(result.level, RiskLevel.HIGH)
                self.assertIn('phrase_threat', indicator_ids(result))
                self.assertIn('direct threat of violence', result.recommendation)
                threat = next(i for i in result.indicators if i.id == 'phrase_threat')
                self.assertEqual(threat.category, IndicatorCategory.SAFETY)

    def test_self_harm_language_gets_supportive_advice(self):
        for text in ('I want to die', 'I want to kill myself', 'I am going to kill myself', 'kill yourself'):
            with self.subTest(text=text):
                result = self.service.scan_message(text)
                self.assertGreaterEqual(result.level, RiskLevel.HIGH)
                self.assertIn('phrase_self_harm', indicator_ids(result))
                self.assertIn('self-harm or suicide', result.recommendation)

    def test_extortion_and_harassment_are_reported(self):
        extortion = self.service.scan_message(
            'I have your photos. Pay me or I will share them with everyone.'
        )
        self.assertGreaterEqual(extortion.level, RiskLevel.HIGH)
        self.assertIn('phrase_extortion', indicator_ids(extortion))
        self.assertIn('blackmail or extortion', extortion.recommendation)

        harassment = self.service.scan_message('You are worthless and nobody likes you.')
        self.assertEqual(harassment.level, RiskLevel.MEDIUM)
        self.assertIn('phrase_harassment', indicator_ids(harassment))
        self.assertIn('abusive or degrading language', harassment.recommendation)

    def test_safety_phrases_use_whole_words(self):
        safe_samples = (
            'I will kill the process before lunch.',
            'I will kill your process and restart it.',
            "I don't want to die, I want to live.",
            'This article is about suicide prevention.',
            'The incident was described as a murder mystery.',
        )
        for text in safe_samples:
            with self.subTest(text=text):
                result = self.service.scan_message(text)
                self.assertEqual(result.level, RiskLevel.LOW, result.indicators)
                self.assertFalse(indicator_ids(result) & {
                    'phrase_threat',
                    'phrase_self_harm',
                    'phrase_extortion',
                    'phrase_harassment',
                })

    def test_safety_weights_are_configurable(self):
        config = self.data.config
        self.assertEqual(config.weight('weight.threat'), 60)
        self.assertEqual(config.weight('weight.self_harm'), 65)
        self.assertEqual(config.weight('weight.extortion'), 50)
        self.assertEqual(config.weight('weight.harassment'), 25)


if __name__ == '__main__':
    unittest.main(verbosity=2)
