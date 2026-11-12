import csv
from pathlib import Path

from detector import load_attempts, analyze

SCENARIOS = {
    "normal": "NORMAL",
    "abnormal_1": "UNAUTHORIZED_EGRESS",
    "abnormal_2": "DESTINATION_FANOUT",
    "abnormal_3": "MULTI_PORT_SCAN",
    "normal_repeat": "NORMAL",
    "abnormal_shortscan": "MULTI_PORT_SCAN",
    "abnormal_slowscan": "MULTI_PORT_SCAN",
}

CONFIGS = {
    "R1_ONLY": {
        "R1_UNAUTHORIZED_EGRESS"
    },
    "R1_R2": {
        "R1_UNAUTHORIZED_EGRESS",
        "R2_DESTINATION_FANOUT",
    },
    "R1_R2_R3": {
        "R1_UNAUTHORIZED_EGRESS",
        "R2_DESTINATION_FANOUT",
        "R3_MULTI_PORT_SCAN",
    },
}


def classify(enabled_rules):
    if "R3_MULTI_PORT_SCAN" in enabled_rules:
        return "MULTI_PORT_SCAN"

    if "R2_DESTINATION_FANOUT" in enabled_rules:
        return "DESTINATION_FANOUT"

    if "R1_UNAUTHORIZED_EGRESS" in enabled_rules:
        return "UNAUTHORIZED_EGRESS"

    return "NORMAL"


def main():
    output_rows = []
    summary_rows = []

    # Apply the same recorded evidence to every configuration.
    observed = {}

    for name in SCENARIOS:
        path = Path(f"results/normalized/{name}.jsonl")
        attempts, skipped = load_attempts(path)
        _, triggered, _ = analyze(attempts)
        observed[name] = triggered

    for config_name, active_rules in CONFIGS.items():
        tp = tn = fp = fn = 0
        exact = 0

        print(f"\n=== {config_name} ===")

        for name, truth in SCENARIOS.items():
            enabled = observed[name] & active_rules
            prediction = classify(enabled)

            match = prediction == truth
            exact += int(match)

            actual_attack = truth != "NORMAL"
            predicted_attack = prediction != "NORMAL"

            if actual_attack and predicted_attack:
                tp += 1
            elif not actual_attack and not predicted_attack:
                tn += 1
            elif not actual_attack:
                fp += 1
            else:
                fn += 1

            print(
                f"{name:20} "
                f"{prediction:22} "
                f"{'PASS' if match else 'FAIL'}"
            )

            output_rows.append({
                "configuration": config_name,
                "scenario": name,
                "ground_truth": truth,
                "prediction": prediction,
                "correct_type": match,
            })

        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0
        )

        exact_accuracy = exact / len(SCENARIOS)

        summary_rows.append({
            "configuration": config_name,
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "binary_f1": round(f1, 4),
            "exact_type_accuracy": round(exact_accuracy, 4),
        })

        print(f"\nBinary F1: {f1:.4f}")
        print(
            f"Exact type accuracy: "
            f"{exact}/{len(SCENARIOS)} "
            f"({exact_accuracy:.1%})"
        )

    Path("results").mkdir(exist_ok=True)

    for filename, rows in [
        ("results/ablation_details.csv", output_rows),
        ("results/ablation_summary.csv", summary_rows),
    ]:
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=list(rows[0].keys()), lineterminator='\n'
            )
            writer.writeheader()
            writer.writerows(rows)

        print(f"\nSaved: {filename}")


if __name__ == "__main__":
    main()
