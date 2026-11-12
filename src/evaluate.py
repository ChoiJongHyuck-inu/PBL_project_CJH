import json
from pathlib import Path

from detector import DATA_DIR, load_attempts, analyze

GROUND_TRUTH = {
    "normal": "NORMAL",
    "abnormal_1": "UNAUTHORIZED_EGRESS",
    "abnormal_2": "DESTINATION_FANOUT",
    "abnormal_3": "MULTI_PORT_SCAN",
}

OUTPUT = Path("results/evaluation.json")


def safe_div(a, b):
    return a / b if b else 0.0


def main():
    tp = tn = fp = fn = 0
    correct_classes = 0
    results = []

    for scenario, truth in GROUND_TRUTH.items():
        path = DATA_DIR / f"{scenario}.jsonl"

        attempts, skipped = load_attempts(path)
        prediction, rules, features = analyze(attempts)

        actual_attack = truth != "NORMAL"
        predicted_attack = prediction != "NORMAL"

        if actual_attack and predicted_attack:
            tp += 1
        elif not actual_attack and not predicted_attack:
            tn += 1
        elif not actual_attack and predicted_attack:
            fp += 1
        else:
            fn += 1

        correct = prediction == truth
        correct_classes += int(correct)

        result = {
            "scenario": scenario,
            "ground_truth": truth,
            "prediction": prediction,
            "correct": correct,
            "attempts": len(attempts),
            "skipped": skipped,
            "triggered_rules": sorted(rules),
        }
        results.append(result)

        print(
            f"{scenario:12} | "
            f"Expected: {truth:20} | "
            f"Predicted: {prediction:20} | "
            f"{'PASS' if correct else 'FAIL'}"
        )

    total = len(results)
    accuracy = safe_div(tp + tn, total)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(
        2 * precision * recall,
        precision + recall,
    )

    report = {
        "note": "Evaluation on four collected scenario files; "
                "not an independent generalization test.",
        "confusion_matrix_binary": {
            "TP": tp, "TN": tn,
            "FP": fp, "FN": fn,
        },
        "metrics_binary": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
        },
        "exact_class_accuracy": safe_div(correct_classes, total),
        "scenarios": results,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n=== Binary Classification Evaluation ===")
    print(f"TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")
    print(f"Exact-class accuracy: {correct_classes}/{total}")
    print(f"\nSaved: {OUTPUT}")


if __name__ == "__main__":
    main()
