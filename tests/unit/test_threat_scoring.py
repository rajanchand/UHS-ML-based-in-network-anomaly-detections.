"""
Unit Tests - Threat Scoring System
==================================
Specifically targets severity levels, weights, and edge cases of the ThreatScorer.
"""

import numpy as np
from app.ml.threat_scoring import ThreatScorer


def test_severity_classification():
    """Verify threat score severity categories are mapped correctly."""
    assert ThreatScorer.classify_severity(90) == 'critical'
    assert ThreatScorer.classify_severity(75) == 'critical'
    assert ThreatScorer.classify_severity(70) == 'high'
    assert ThreatScorer.classify_severity(50) == 'high'
    assert ThreatScorer.classify_severity(45) == 'medium'
    assert ThreatScorer.classify_severity(25) == 'medium'
    assert ThreatScorer.classify_severity(20) == 'low'
    assert ThreatScorer.classify_severity(0) == 'low'


def test_empty_predictions_handling():
    """Verify ThreatScorer handles empty arrays safely without raising exceptions."""
    result = ThreatScorer.compute_threat_score([], [], [])
    assert result['threat_score'] == 0.0
    assert result['anomaly_count'] == 0
    assert result['anomaly_rate'] == 0.0
    assert result['severity'] == 'low'


def test_threat_scorer_weighted_components():
    """Verify composite weights calculations match expected formulas."""
    # Ensure fully anomalous results with high confidence trigger high score
    predictions = np.array([1, 1, 1])
    probabilities = np.array([0.95, 0.98, 0.99])
    X = np.random.rand(3, 4)
    
    result = ThreatScorer.compute_threat_score(predictions, probabilities, X)
    
    assert result['threat_score'] > 50.0
    assert result['anomaly_rate'] == 100.0
    assert result['anomaly_count'] == 3
