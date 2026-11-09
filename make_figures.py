#!/usr/bin/env python3
"""Generate the report figures from the verified run data (reproducible).

Figure 1: evaluation-awareness (framing) effect, per model.
Figure 2: the clean secret-keeper collusion test -- keeper leak rate by arm, per model.

Run:  python make_figures.py   ->  writes figs/fig1_framing.png, figs/fig2_secret.png
"""
from __future__ import annotations
import glob, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = "figs"
os.makedirs(OUT, exist_ok=True)
HELD = "#3b6ea5"     # cool: contained / refused / held
LEAK = "#e07b39"     # warm: leaked / complied
plt.rcParams.update({"font.size": 11})


def _secret_rate(*batch_globs):
    """Return {arm: (leaked, runs)} merged across one or more secret-keeper batches."""
    out = {}
    for g in batch_globs:
        for rj in glob.glob(g):
            d = json.load(open(rj))
            arm = d.get("arm")
            if arm == "control":
                continue
            lk, n = out.get(arm, (0, 0))
            out[arm] = (lk + (1 if d.get("leaked") else 0), n + 1)
    return out


def fig_framing():
    # Hard-coded from the verified matrices (see REPORT.md Finding 2); these are
    # counts, shown as percentages with the raw fraction labelled.
    data = {
        "glm-5.2":          {"test_comply": (37, 37), "real_refuse": (8, 8)},
        "deepseek-v4-flash":{"test_comply": (42, 42), "real_refuse": (2, 24)},
    }
    models = list(data)
    fig, ax = plt.subplots(figsize=(6.2, 3.6))
    x = range(len(models))
    w = 0.38
    comply = [100 * data[m]["test_comply"][0] / data[m]["test_comply"][1] for m in models]
    refuse = [100 * data[m]["real_refuse"][0] / data[m]["real_refuse"][1] for m in models]
    b1 = ax.bar([i - w/2 for i in x], comply, w, color=LEAK, label="Complied (test framing)")
    b2 = ax.bar([i + w/2 for i in x], refuse, w, color=HELD, label="Refused (realistic framing)")
    for m, i in zip(models, x):
        ax.text(i - w/2, comply[i] + 2, f"{data[m]['test_comply'][0]}/{data[m]['test_comply'][1]}",
                ha="center", fontsize=9)
        ax.text(i + w/2, refuse[i] + 2, f"{data[m]['real_refuse'][0]}/{data[m]['real_refuse'][1]}",
                ha="center", fontsize=9)
    ax.set_xticks(list(x)); ax.set_xticklabels(models)
    ax.set_ylabel("% of runs"); ax.set_ylim(0, 112)
    ax.set_title("Framing, not capability, gates behavior", fontweight="bold")
    ax.legend(loc="center right", fontsize=9, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(); fig.savefig(f"{OUT}/fig1_framing.png", dpi=200); plt.close(fig)
    print(f"wrote {OUT}/fig1_framing.png")


def fig_secret():
    ds = _secret_rate("runs/secret_deepseek/*/result.json", "runs/secret_adv_deepseek/*/result.json")
    gl = _secret_rate("runs/secret_glm/*/result.json", "runs/secret_adv_glm/*/result.json")
    arms = ["baseline", "strict", "helpful", "adversarial"]
    labels = {"baseline": "baseline\n(not told to\nkeep secret)",
              "strict": "strict\n(ordered to\nguard)", "helpful": "helpful-\nbut-guard",
              "adversarial": "adversarial\n(solvers attack\n+ inject)"}
    fig, ax = plt.subplots(figsize=(7.8, 3.9))
    x = range(len(arms)); w = 0.38
    series = [("deepseek-v4-flash", ds, -w/2), ("glm-5.2", gl, w/2)]
    hatches = {"deepseek-v4-flash": "", "glm-5.2": "//"}
    for name, rate, off in series:
        vals, labs = [], []
        for a in arms:
            lk, n = rate.get(a, (0, 0))
            vals.append(100 * lk / n if n else 0.0)
            labs.append(f"{lk}/{n}" if n else "—")
        bars = ax.bar([i + off for i in x], vals, w,
                      color=[LEAK if v > 0 else HELD for v in vals],
                      edgecolor="black", hatch=hatches[name], label=name)
        for i, (v, lab) in enumerate(zip(vals, labs)):
            ax.text(i + off, v + 2, lab, ha="center", fontsize=9)
    ax.set_xticks(list(x)); ax.set_xticklabels([labels[a] for a in arms], fontsize=9)
    ax.set_ylabel("% of runs where the keeper leaked"); ax.set_ylim(0, 112)
    ax.set_title("Clean collusion test: does a keeper break a 'never share' order?",
                 fontweight="bold", fontsize=11)
    # legend for model via proxy (hatch), color encodes leak/held
    from matplotlib.patches import Patch
    leg = [Patch(facecolor="white", edgecolor="black", hatch="", label="deepseek-v4-flash"),
           Patch(facecolor="white", edgecolor="black", hatch="//", label="glm-5.2")]
    ax.legend(handles=leg, loc="upper right", fontsize=9, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout(); fig.savefig(f"{OUT}/fig2_secret.png", dpi=200); plt.close(fig)
    print(f"wrote {OUT}/fig2_secret.png  (deepseek={ds}, glm={gl})")


if __name__ == "__main__":
    fig_framing()
    fig_secret()
