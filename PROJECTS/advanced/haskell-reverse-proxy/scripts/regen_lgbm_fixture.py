"""
©AngelaMos | 2026
regen_lgbm_fixture.py
"""

# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "lightgbm>=4.0,<5",
#     "numpy>=1.26",
# ]
# ///

import lightgbm as lgb
import numpy as np
from pathlib import Path


OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent / "test" / "fixtures" / "ml" /
    "regen_sample_v4.txt"
)
NUM_FEATURES = 4
NUM_SAMPLES = 200
NUM_LEAVES = 7
NUM_BOOST_ROUND = 3
RANDOM_SEED = 42
CAT_FEATURE_COL = 3
CAT_VALUES = [0, 1, 2, 3]
NOISE_SCALE = 0.5
LEARNING_RATE = 0.1
MIN_DATA_IN_LEAF = 5
MIN_DATA_PER_GROUP = 5
WEIGHT_FEAT_0 = 1.0
WEIGHT_FEAT_1 = 0.5
WEIGHT_FEAT_2 = -1.0


def make_dataset() -> tuple[np.ndarray, np.ndarray]:
    """
    Build a deterministic synthetic dataset with one categorical feature
    """
    rng = np.random.default_rng(RANDOM_SEED)
    features = rng.normal(0, 1, (NUM_SAMPLES, NUM_FEATURES))
    features[:, CAT_FEATURE_COL] = rng.choice(CAT_VALUES, size = NUM_SAMPLES)
    signal = (
        WEIGHT_FEAT_0 * features[:,
                                 0] + WEIGHT_FEAT_1 * features[:,
                                                               1] +
        WEIGHT_FEAT_2 * features[:,
                                 2]
    )
    noise = rng.normal(0, NOISE_SCALE, NUM_SAMPLES)
    labels = ((signal + noise) > 0).astype(int)
    return features, labels


def train_model(features: np.ndarray, labels: np.ndarray) -> lgb.Booster:
    """
    Train a tiny binary GBDT with one categorical feature
    """
    dataset = lgb.Dataset(
        features,
        label = labels,
        categorical_feature = [CAT_FEATURE_COL],
        feature_name = [f"feat{i}" for i in range(NUM_FEATURES)],
    )
    params = {
        "objective": "binary",
        "num_leaves": NUM_LEAVES,
        "learning_rate": LEARNING_RATE,
        "verbose": -1,
        "min_data_in_leaf": MIN_DATA_IN_LEAF,
        "min_data_per_group": MIN_DATA_PER_GROUP,
    }
    return lgb.train(params, dataset, num_boost_round = NUM_BOOST_ROUND)


def main() -> None:
    """
    Train the booster and save it to the regen fixture path
    """
    features, labels = make_dataset()
    booster = train_model(features, labels)
    OUTPUT_PATH.parent.mkdir(parents = True, exist_ok = True)
    booster.save_model(str(OUTPUT_PATH))
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
