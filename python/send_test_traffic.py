import time
import requests

WAF_URL  = "http://localhost:8080/"

def normal_traffic():
    "Simulates A real git clinet - should be allowed."
    headers = {"User-Agent": "git/2.39.2"}
    for _ in range(3):
        r = requests.get(WAF_URL, headers=headers)
        print(f"[normal]            status={r.status_code}")
        time.sleep(1)

def suspicious_user_agents():
    "Kown bad/toling User-Agents - should be blocked."
    bad_uas = [
        "python-requests/2.31",
        "Go-http-client/1.1",
        "",
        "curl/7.81.0",
    ]
    for ua in bad_uas:
        r = requests.get(WAF_URL, headers={"User-Agent": ua})
        print(f"[suspicous]         ua={ua!r:30}        status={r.status_code}")
        time.sleep(0.5)


def beacon_traffic():
    "Verry regualr check-in interval - should get FLAGGED (not blocked, since AutoBlockOnBeacon defaults to false.)"
    headers = {"User-Agent": "git/2.39.2"}
    print(f"[beacon] sending 6 requests, ~5s appart")
    for i in range(6):
        r = requests.get(WAF_URL, headers=headers)
        print(f"[Beacon]        request {i + 1}     status_code{r.status_code}")
        time.sleep(5)


if __name__ == "__main__":
    print("===  Normal Traffic  ===")
    normal_traffic()

    print("\n   === Suspicious User-Agents  ===  ")
    suspicious_user_agents()

    print("\n   === beacon-like traffic (watch waf.log for FLAGGED) ===")
    beacon_traffic()

    print("\n   === Done Check waf.log for BLOCKED/FLAGED lines")