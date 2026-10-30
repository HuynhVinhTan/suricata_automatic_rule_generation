"""Lab-only benign-trained ML/DL anomaly experiment."""

import csv
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from netids.models.autoencoder import NumpyAutoencoder


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / "data" / "private" / "lab-sessions"
OUTPUT = ROOT / "data" / "private" / "lab-models" / "lab_syn_anomaly_v0_1"

FEATURES = [
    "syn_count",
    "unique_dst_ports",
    "repeated_probes",
    "median_inter_syn_seconds",
    "syn_rate_per_second",
]

DATASETS = {
    "normal-train": {
        "folder": "normal-batch-v01",
        "pcap": "normal-train.pcap",
        "sha": "b79b45a8c62394a1fbb7284b4c3beead4139f51ab30438db5ea4df1bea46036a",
        "rows": 58,
        "label": "NORMAL",
    },
    "normal-cal": {
        "folder": "normal-batch-v01",
        "pcap": "normal-cal.pcap",
        "sha": "3920256b68ac424b2296c62554d89637f32fba18ffa9fac4c3a62cb6d2cec5a0",
        "rows": 30,
        "label": "NORMAL",
    },
    "normal-test": {
        "folder": "normal-batch-v01",
        "pcap": "normal-test.pcap",
        "sha": "70bf24bed9a1895390151a0ef2f55dc2f99652b15de5c60a4a9a760b3c489b51",
        "rows": 29,
        "label": "NORMAL",
    },
    "slow-scan-s01": {
        "folder": "slow-scan-s01",
        "pcap": "traffic.pcap",
        "sha": "381652cb04c14dea565dee61cb77b151bf80571c531c76501aff97c480420c03",
        "rows": 6,
        "label": "ATTACK",
    },
}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dataset(name, spec):
    directory = PRIVATE / spec["folder"]
    pcap = directory / spec["pcap"]
    csv_path = directory / f"syn_windows_10s_{name}.csv"

    if sha256(pcap) != spec["sha"]:
        raise RuntimeError(f"{name}: PCAP checksum mismatch")

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if len(rows) != spec["rows"]:
        raise RuntimeError(f"{name}: unexpected feature row count")

    required = set(FEATURES) | {
        "label", "window_seconds", "window_index"
    }

    if not required.issubset(rows[0]):
        raise RuntimeError(f"{name}: feature schema mismatch")

    indices = []

    for row in rows:
        if row["label"] != spec["label"]:
            raise RuntimeError(f"{name}: label mismatch")

        if int(row["window_seconds"]) != 10:
            raise RuntimeError(f"{name}: wrong window size")

        indices.append(int(row["window_index"]))

        count = int(row["syn_count"])
        unique = int(row["unique_dst_ports"])
        repeated = int(row["repeated_probes"])

        if count < 1 or unique < 1 or unique > count:
            raise RuntimeError(f"{name}: invalid SYN features")

        if repeated != count - unique:
            raise RuntimeError(f"{name}: repeated-probe mismatch")

        if abs(float(row["syn_rate_per_second"]) - count / 10) > 1e-5:
            raise RuntimeError(f"{name}: SYN rate mismatch")

    if indices != sorted(set(indices)):
        raise RuntimeError(f"{name}: invalid window indices")

    values = np.asarray(
        [[float(row[key]) for key in FEATURES] for row in rows],
        dtype=np.float64,
    )

    if not np.isfinite(values).all():
        raise RuntimeError(f"{name}: non-finite features")

    print(f"PASS: {name} ({len(values)} windows) verified")
    return values, sha256(csv_path)


def checked_scores(values, expected_size, name):
    scores = np.asarray(values, dtype=np.float64).reshape(-1)

    if scores.size != expected_size:
        raise RuntimeError(f"{name}: score length mismatch")

    if not np.isfinite(scores).all():
        raise RuntimeError(f"{name}: non-finite anomaly score")

    return scores


def evaluation(normal_scores, attack_scores, threshold):
    fp = int(np.sum(normal_scores > threshold))
    detected = int(np.sum(attack_scores > threshold))

    return {
        "normal_test_windows": int(len(normal_scores)),
        "normal_false_alert_windows": fp,
        "normal_active_window_fpr": float(fp / len(normal_scores)),
        "attack_windows": int(len(attack_scores)),
        "attack_flagged_windows": detected,
        "attack_window_detection_fraction": float(
            detected / len(attack_scores)
        ),
        "attack_session_detected": bool(detected > 0),
        "attack_window_flags": [
            int(value > threshold) for value in attack_scores
        ],
    }


def main():
    print("=== LAB ML AND DL TRAINING ===")

    if OUTPUT.exists():
        raise SystemExit("ERROR: Model output already exists")

    data = {}
    csv_hashes = {}

    for name, spec in DATASETS.items():
        data[name], csv_hashes[name] = load_dataset(name, spec)

    # Every scaler/model fit uses NORMAL training only.
    scaler = StandardScaler()

    x_train = scaler.fit_transform(data["normal-train"])
    x_cal = scaler.transform(data["normal-cal"])
    x_normal_test = scaler.transform(data["normal-test"])
    x_attack = scaler.transform(data["slow-scan-s01"])

    # Keep early stopping separate from threshold calibration.
    x_early = x_cal[:15]
    x_threshold = x_cal[15:]

    print("Training NORMAL windows:", len(x_train))
    print("DL early-stop NORMAL windows:", len(x_early))
    print("Threshold NORMAL windows:", len(x_threshold))

    print()
    print("=== MACHINE LEARNING: ISOLATION FOREST ===")

    forest = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=1,
    )

    forest.fit(x_train)

    # Larger value means more anomalous.
    if_cal = checked_scores(
        -forest.score_samples(x_threshold),
        len(x_threshold),
        "IF calibration",
    )
    if_normal = checked_scores(
        -forest.score_samples(x_normal_test),
        len(x_normal_test),
        "IF normal test",
    )
    if_attack = checked_scores(
        -forest.score_samples(x_attack),
        len(x_attack),
        "IF attack",
    )

    if_threshold = float(np.quantile(if_cal, 0.95))

    print("PASS: ISOLATION FOREST FIT COMPLETED")

    print()
    print("=== DEEP LEARNING: NUMPY AUTOENCODER ===")

    ae = NumpyAutoencoder(
        input_dim=len(FEATURES),
        hidden_dim=8,
        bottleneck_dim=2,
        epochs=120,
        patience=15,
        random_state=42,
    )

    ae.fit(x_train, x_early)

    ae_cal = checked_scores(
        ae.anomaly_score(x_threshold),
        len(x_threshold),
        "AE calibration",
    )
    ae_normal = checked_scores(
        ae.anomaly_score(x_normal_test),
        len(x_normal_test),
        "AE normal test",
    )
    ae_attack = checked_scores(
        ae.anomaly_score(x_attack),
        len(x_attack),
        "AE attack",
    )

    ae_threshold = float(np.quantile(ae_cal, 0.95))

    print("PASS: AUTOENCODER FIT COMPLETED")

    metrics = {
        "IsolationForest": evaluation(
            if_normal, if_attack, if_threshold
        ),
        "NumpyAutoencoder": evaluation(
            ae_normal, ae_attack, ae_threshold
        ),
    }

    report = {
        "experiment": "lab_syn_anomaly_v0_1",
        "window_seconds": 10,
        "feature_names": FEATURES,
        "training_policy": "NORMAL_ONLY",
        "train_windows": len(x_train),
        "early_stop_normal_windows": len(x_early),
        "threshold_normal_windows": len(x_threshold),
        "normal_test_windows": len(x_normal_test),
        "attack_windows": len(x_attack),
        "threshold_quantile": 0.95,
        "thresholds": {
            "IsolationForest": if_threshold,
            "NumpyAutoencoder": ae_threshold,
        },
        "pcap_sha256": {
            name: spec["sha"] for name, spec in DATASETS.items()
        },
        "feature_csv_sha256": csv_hashes,
        "metrics": metrics,
        "limitations": [
            "One attack session with six correlated windows",
            "Normal captures cover only controlled HTTP and SSH",
            "Only windows containing a SYN are represented",
            "Fixed 10-second window features include redundancy",
            "Reported rates are not population performance estimates",
        ],
    }

    OUTPUT.mkdir(parents=True, exist_ok=False)

    bundle = {
        "scaler": scaler,
        "isolation_forest": forest,
        "autoencoder": ae,
        "features": FEATURES,
        "window_seconds": 10,
        "thresholds": report["thresholds"],
    }

    model_path = OUTPUT / "models.joblib"
    joblib.dump(bundle, model_path, compress=3)

    # Confirm saved model can be reloaded and produces the same scores.
    restored = joblib.load(model_path)

    reloaded_if = -restored["isolation_forest"].score_samples(
        restored["scaler"].transform(data["slow-scan-s01"])
    )
    reloaded_ae = restored["autoencoder"].anomaly_score(
        restored["scaler"].transform(data["slow-scan-s01"])
    )

    if not np.allclose(reloaded_if, if_attack, rtol=1e-8, atol=1e-10):
        raise RuntimeError("Isolation Forest reload mismatch")

    if not np.allclose(reloaded_ae, ae_attack, rtol=1e-8, atol=1e-10):
        raise RuntimeError("Autoencoder reload mismatch")

    report_path = OUTPUT / "report.json"

    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print("=== LAB ML AND DL EVALUATION RESULTS ===")

    for name, result in metrics.items():
        print(name)
        print(
            "  Normal false alerts:",
            result["normal_false_alert_windows"],
            "/", result["normal_test_windows"],
        )
        print(
            "  Normal active-window FPR:",
            round(result["normal_active_window_fpr"], 4),
        )
        print(
            "  Attack windows flagged:",
            result["attack_flagged_windows"],
            "/", result["attack_windows"],
        )
        print(
            "  Attack session detected:",
            result["attack_session_detected"],
        )
        print(
            "  Attack window flags:",
            result["attack_window_flags"],
        )

    print("Saved model:", model_path)
    print("Saved report:", report_path)
    print("Model reload equivalence: PASS")
    print("No existing models or live Suricata rules modified.")
    print("PASS: LAB ML AND DL EVALUATION COMPLETE")


if __name__ == "__main__":
    main()