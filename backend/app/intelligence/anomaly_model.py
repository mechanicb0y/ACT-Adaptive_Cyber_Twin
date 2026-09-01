#The ML anomaly score: how far an attacker's activity is from normal.
#
#Two implementations behind one interface:
#
#  * IsolationForestScorer  uses scikit-learn. It trains on a baseline of normal
#    traffic and flags outliers. This is the real machine learning path.
#  * StatisticalScorer      pure Python. Scores deviation from expected baselines
#    with no dependency at all.
#
#`build_anomaly_scorer()` returns the ML one if scikit-learn is installed,
#otherwise the statistical one, so ACT runs everywhere and gets smarter when the
#library is present. Both return a score from 0 (normal) to 1 (highly abnormal).

import math
import random
from typing import List, Protocol

from app.intelligence.feature_extractor import FEATURE_NAMES, FeatureVector

#what "normal" activity looks like, per feature, used by both scorers as a
#baseline. A quiet host: few events, no failures, one internal user, day time.
NORMAL_BASELINE = {
    "total_events": 3,
    "failed_logins": 0,
    "distinct_users": 1,
    "distinct_ips": 1,
    "events_per_minute": 0.2,
    "off_hours": 0,
    "external_source": 0,
    "privileged_target": 0,
    "compromised": 0,
    "deepest_stage": 0,
}

#how much each feature matters when measuring abnormality
FEATURE_WEIGHTS = {
    "total_events": 0.6,
    "failed_logins": 1.3,
    "distinct_users": 1.0,
    "distinct_ips": 1.0,
    "events_per_minute": 1.1,
    "off_hours": 0.8,
    "external_source": 1.0,
    "privileged_target": 0.9,
    "compromised": 1.6,
    "deepest_stage": 1.2,
}


class AnomalyScorer(Protocol):
    name: str
    def score(self, vector: FeatureVector) -> float: ...


class StatisticalScorer:
    """Deviation-from-baseline score, pure Python, always available."""

    name = "statistical"

    def __init__(self, baseline=NORMAL_BASELINE, weights=FEATURE_WEIGHTS):
        self.baseline = baseline
        self.weights = weights

    def score(self, vector: FeatureVector) -> float:

        values = vector.as_dict()

        total = 0.0
        weight_sum = 0.0

        for name in FEATURE_NAMES:

            expected = self.baseline.get(name, 0)
            weight = self.weights.get(name, 1.0)
            actual = values.get(name, 0.0)

            #how far above normal, in soft relative units
            excess = max(0.0, actual - expected)
            scale = max(1.0, float(expected) + 1.0)

            #saturating curve so one huge value cannot dominate everything
            contribution = 1.0 - math.exp(-excess / scale)

            total += weight * contribution
            weight_sum += weight

        return round(total / weight_sum, 4) if weight_sum else 0.0


class IsolationForestScorer:
    """scikit-learn IsolationForest, trained on a generated normal baseline."""

    name = "isolation-forest"

    def __init__(self, samples: int = 400, seed: int = 42):
        from sklearn.ensemble import IsolationForest   #imported lazily on purpose

        self._model = IsolationForest(
            n_estimators=120, contamination=0.08, random_state=seed
        )
        self._model.fit(self._training_data(samples, seed))

    def _training_data(self, samples: int, seed: int) -> List[List[float]]:
        #synthesise a cloud of "normal quiet host" vectors to learn from
        rng = random.Random(seed)
        rows = []
        for _ in range(samples):
            rows.append([
                rng.uniform(0, 6),      #total_events
                rng.uniform(0, 1),      #failed_logins
                rng.uniform(1, 2),      #distinct_users
                rng.uniform(1, 2),      #distinct_ips
                rng.uniform(0, 0.5),    #events_per_minute
                0.0,                    #off_hours
                0.0,                    #external_source
                0.0,                    #privileged_target
                0.0,                    #compromised
                rng.uniform(0, 1),      #deepest_stage
            ])
        return rows

    def score(self, vector: FeatureVector) -> float:
        #score_samples: higher = more normal. Map to 0..1 abnormal.
        raw = self._model.score_samples([vector.values])[0]
        return round(max(0.0, min(1.0, 0.5 - raw)), 4)


def build_anomaly_scorer() -> AnomalyScorer:
    #prefer real ML, fall back to the statistical scorer if sklearn is absent
    try:
        return IsolationForestScorer()
    except Exception:                                   # noqa: BLE001
        return StatisticalScorer()
