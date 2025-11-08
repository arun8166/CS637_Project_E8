import os, time, requests, random

BASE = os.environ.get("SBOS_BASE", "http://localhost:8083")
API_KEY = os.environ["SBOS_APP_KEY"]  # injected by App Steward

def get_caps():
    r = requests.get(f"{BASE}/capabilities", headers={"X-App-Key": API_KEY}, timeout=5)
    r.raise_for_status()
    return r.json()["points"]

def write_point(label, value, prev=None):
    body = {"point_label": label, "value": value, "prev_value": prev}
    r = requests.post(f"{BASE}/write", json=body, headers={"X-App-Key": API_KEY}, timeout=5)
    return r.status_code, r.text

def main():
    caps = get_caps()
    cool_labels = [p["label"] for p in caps if "Cool_SP" in p["label"]]
    if not cool_labels:
        print("No cooling point in capability; exiting")
        return
    lbl = cool_labels[0]
    prev = 22.0
    for _ in range(10):
        delta = random.uniform(-1.0, 1.0)
        val = max(19.0, min(26.0, prev + delta))
        code, txt = write_point(lbl, val, prev)
        print("write", lbl, val, "->", code, txt)
        if code == 200:
            prev = val
        time.sleep(0.5)

if __name__ == "__main__":
    main()
