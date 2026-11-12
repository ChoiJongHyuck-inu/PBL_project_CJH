import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

INPUT = Path("results/ablation_summary.csv")
OUTPUT = Path("results/figures/ablation_comparison.png")

with INPUT.open(encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

labels = {
    "R1_ONLY": "R1",
    "R1_R2": "R1 + R2",
    "R1_R2_R3": "R1 + R2 + R3",
}

names = [labels[r["configuration"]] for r in rows]
binary_f1 = [float(r["binary_f1"]) * 100 for r in rows]
type_acc = [
    float(r["exact_type_accuracy"]) * 100
    for r in rows
]

x = np.arange(len(names))
width = 0.35

fig, ax = plt.subplots(figsize=(9, 5.5))

bars1 = ax.bar(
    x - width / 2,
    binary_f1,
    width,
    label="Binary Detection F1",
    color="#7AA6C2",
)

bars2 = ax.bar(
    x + width / 2,
    type_acc,
    width,
    label="Exact Attack-Type Accuracy",
    color="#2875A8",
)

ax.set_title(
    "Ablation Study: Contribution of Detection Rules",
    fontsize=14,
    pad=15,
)

ax.set_ylabel("Score (%)")
ax.set_xlabel("Enabled Detection Rules")
ax.set_xticks(x)
ax.set_xticklabels(names)
ax.set_ylim(0, 115)

ax.legend(loc="upper left")
ax.grid(axis="y", alpha=0.2)
ax.set_axisbelow(True)

for bars in [bars1, bars2]:
    for bar in bars:
        value = bar.get_height()

        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 2,
            f"{value:.1f}%",
            ha="center",
            fontsize=10,
        )

fig.tight_layout()
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUTPUT, dpi=200)
plt.close(fig)

print("Saved:", OUTPUT)
print("\n=== Ablation Results ===")

for name, f1, acc in zip(names, binary_f1, type_acc):
    print(
        f"{name:15} "
        f"Binary F1={f1:.1f}%  "
        f"Type Accuracy={acc:.1f}%"
    )
