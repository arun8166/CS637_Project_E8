# plot_results.py
import os, sqlite3, math, time, json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import requests

BASE = os.environ.get("SBOS_BASE", "http://localhost:8083")
DB_PATH = "sbos.db"
OUT = Path("plots")
OUT.mkdir(exist_ok=True)

sns.set_theme(style="whitegrid")

def load_timeseries():
    con = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql("SELECT ts, point_label, value FROM timeseries ORDER BY ts ASC", con)
        return df
    finally:
        con.close()

def load_txlog():
    con = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql("SELECT ts, actor, app_id, user_id, action, point_label, value, decision, reason FROM txlog ORDER BY ts ASC", con)
        return df
    finally:
        con.close()

def get_health():
    try:
        r = requests.get(f"{BASE}/health", timeout=5)
        return r.json()
    except Exception:
        return {"status":"unreachable"}

def plot_timeseries(df_ts):
    if df_ts.empty:
        print("No timeseries data to plot.")
        return
    
    df = df_ts.copy()
    df["t"] = pd.to_datetime(df["ts"], unit="s")
    
    plt.figure(figsize=(10,6))
    for label, dfg in df.groupby("point_label"):
        plt.plot(dfg["t"], dfg["value"], label=label)
    plt.title("Setpoint Time Series")
    plt.xlabel("Time")
    plt.ylabel("Value")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig(OUT / "timeseries.png", dpi=150)
    plt.close()

def plot_enforcement_bars(df_tx):
    if df_tx.empty:
        print("No txlog data to plot.")
        return
    
    dec_counts = df_tx.groupby("decision").size().reset_index(name="count")
    plt.figure(figsize=(6,4))
    sns.barplot(data=dec_counts, x="decision", y="count", color="#69b3a2")
    plt.title("Write Decisions (All Actors)")
    plt.xlabel("Decision")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(OUT / "decisions_overall.png", dpi=150)
    plt.close()

    
    denies = df_tx[(df_tx["decision"]=="deny") & (df_tx["actor"]=="regulator")]
    if not denies.empty:
        rs = denies.groupby("reason").size().reset_index(name="count").sort_values("count", ascending=False)
        plt.figure(figsize=(10,5))
        sns.barplot(data=rs, x="reason", y="count", color="#d95f02")
        plt.title("Denied Writes by Reason (Regulator)")
        plt.xlabel("Reason")
        plt.ylabel("Count")
        plt.xticks(rotation=30, ha="right")
        plt.tight_layout()
        plt.savefig(OUT / "denied_by_reason.png", dpi=150)
        plt.close()

def plot_requests_per_minute(df_tx):
    if df_tx.empty:
        return
    df = df_tx.copy()
    df["t"] = pd.to_datetime(df["ts"], unit="s")
    df["minute"] = df["t"].dt.floor("T")
    writes = df[df["action"]=="write"].groupby("minute").size().reset_index(name="writes")
    allow = df[(df["action"]=="write") & (df["decision"]=="allow")].groupby("minute").size().reset_index(name="allow")
    deny = df[(df["action"]=="write") & (df["decision"]=="deny")].groupby("minute").size().reset_index(name="deny")
    agg = writes.merge(allow, on="minute", how="left").merge(deny, on="minute", how="left").fillna(0)

    plt.figure(figsize=(10,5))
    plt.plot(agg["minute"], agg["writes"], label="Write attempts", lw=2)
    plt.plot(agg["minute"], agg["allow"], label="Allowed", lw=2)
    plt.plot(agg["minute"], agg["deny"], label="Denied", lw=2)
    plt.title("Writes per Minute (Attempts vs Allowed/Denied)")
    plt.xlabel("Minute")
    plt.ylabel("Count")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig(OUT / "writes_per_minute.png", dpi=150)
    plt.close()

def main():
    h = get_health()
    print("Health:", h)

    ts = load_timeseries()
    tx = load_txlog()

    print(f"Timeseries rows: {len(ts)}")
    print(f"Txlog rows: {len(tx)}")

    plot_timeseries(ts)
    plot_enforcement_bars(tx)
    plot_requests_per_minute(tx)

    print(f"Saved plots to {OUT.resolve()}")

if __name__ == "__main__":
    main()
