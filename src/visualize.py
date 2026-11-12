import csv
import json
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import detector

RAW_DIR = Path("results/raw")
NORMALIZED_DIR = Path("results/normalized")
FIG_DIR = Path("results/figures")
FIG_DIR.mkdir(parents=True, exist_ok=True)

SCENARIOS = {
    "normal": "NORMAL",
    "abnormal_1": "UNAUTHORIZED_EGRESS",
    "abnormal_2": "DESTINATION_FANOUT",
    "abnormal_3": "MULTI_PORT_SCAN",
    "normal_repeat": "NORMAL",
    "abnormal_shortscan": "MULTI_PORT_SCAN",
    "abnormal_slowscan": "MULTI_PORT_SCAN",
}


def raw_counts(name):
    counts = Counter()

    with (RAW_DIR / f"{name}.jsonl").open() as f:
        for line in f:
            if not line.strip():
                continue

            record = json.loads(line)
            flow = record.get("flow") or record
            counts[flow.get("verdict", "UNKNOWN")] += 1

    return counts


def create_summary():
    rows = []

    for name, truth in SCENARIOS.items():
        counts = raw_counts(name)

        attempts, skipped = detector.load_attempts(
            NORMALIZED_DIR / f"{name}.jsonl"
        )

        prediction, rules, _ = detector.analyze(attempts)

        rows.append({
            "scenario": name,
            "ground_truth": truth,
            "prediction": prediction,
            "correct": prediction == truth,
            "raw_events": sum(counts.values()),
            "forwarded_events": counts["FORWARDED"],
            "dropped_events": counts["DROPPED"],
            "normalized_attempts": len(attempts),
            "triggered_rules": ";".join(sorted(rules)),
        })

    path = Path("results/scenario_summary.csv")

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys(), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)

    print("Saved:", path)
    return rows


def plot_dropped_events(rows):
    names = [r["scenario"] for r in rows]
    values = [r["dropped_events"] for r in rows]

    fig, ax = plt.subplots(figsize=(11, 5))

    bars = ax.bar(names, values)

    ax.set_title("Hubble Policy-Dropped Events by Scenario")
    ax.set_ylabel("DROPPED events")
    ax.grid(axis="y", alpha=0.2)
    ax.set_axisbelow(True)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            str(value),
            ha="center",
            fontsize=9,
        )

    ax.set_ylim(0, max(values) * 1.18 + 1)
    plt.xticks(rotation=20, ha="right")
    fig.tight_layout()

    path = FIG_DIR / "dropped_events.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)

    print("Saved:", path)


def plot_window_comparison():
    windows = [60, 120, 180, 240]
    scores = []

    original_window = detector.WINDOW_SECONDS

    try:
        for window in windows:
            detector.WINDOW_SECONDS = window
            correct = 0

            for name, truth in SCENARIOS.items():
                attempts, _ = detector.load_attempts(
                    NORMALIZED_DIR / f"{name}.jsonl"
                )

                prediction, _, _ = detector.analyze(attempts)

                if prediction == truth:
                    correct += 1

            scores.append(100 * correct / len(SCENARIOS))
    finally:
        detector.WINDOW_SECONDS = original_window

    fig, ax = plt.subplots(figsize=(8, 5))

    bars = ax.bar(
        [str(w) for w in windows],
        scores,
        width=0.55,
    )

    ax.set_title("Detection Window Comparison")
    ax.set_xlabel("Sliding window (seconds)")
    ax.set_ylabel("Exact classification accuracy (%)")
    ax.set_ylim(0, 110)
    ax.grid(axis="y", alpha=0.2)
    ax.set_axisbelow(True)

    for bar, value in zip(bars, scores):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 2,
            f"{value:.1f}%",
            ha="center",
            fontsize=10,
        )

    fig.tight_layout()

    path = FIG_DIR / "window_comparison.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)

    print("Saved:", path)
    print("Window scores:", dict(zip(windows, scores)))


if __name__ == "__main__":
    print("=== Generating PBL Results ===")

    rows = create_summary()
    plot_dropped_events(rows)
    plot_window_comparison()

    print("\nAll visualizations generated successfully.")
