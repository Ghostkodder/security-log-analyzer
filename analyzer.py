from collections import Counter, defaultdict

LOG_FILE = "auth.log"
FAILED_LOGIN_THRESHOLD = 3

failed_logins = Counter()
users_by_ip = defaultdict(set)
events = []

try:
    with open(LOG_FILE, "r") as log_file:
        for line in log_file:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 4:
                continue

            timestamp = f"{parts[0]} {parts[1]}"
            event_type = parts[2]

            user = parts[3].split("=")[1]
            ip = parts[4].split("=")[1]

            events.append({
                "timestamp": timestamp,
                "event": event_type,
                "user": user,
                "ip": ip
            })

            users_by_ip[ip].add(user)

            if event_type == "LOGIN_FAILED":
                failed_logins[ip] += 1

except FileNotFoundError:
    print(f"ERROR: Could not find {LOG_FILE}")
    print("Make sure auth.log is in the same folder as analyzer.py")
    exit()

print("=" * 50)
print("SECURITY LOG ANALYZER")
print("=" * 50)

print("\nFAILED LOGIN ATTEMPTS")
print("-" * 50)

for ip, count in failed_logins.items():
    print(f"{ip}: {count}")

print("\nSUSPICIOUS ACTIVITY")
print("-" * 50)

suspicious_ips = []

for ip, count in failed_logins.items():
    if count >= FAILED_LOGIN_THRESHOLD:
        suspicious_ips.append(ip)

        users = ", ".join(users_by_ip[ip])

        print(
            f"ALERT: {ip} had {count} failed login attempts "
            f"against user(s): {users}"
        )

if not suspicious_ips:
    print("No suspicious activity detected.")

print("\nPOST-FAILURE SUCCESSFUL LOGINS")
print("-" * 50)

for i, event in enumerate(events):
    if event["event"] == "LOGIN_SUCCESS":
        previous_events = events[:i]

        failures = [
            previous
            for previous in previous_events
            if previous["event"] == "LOGIN_FAILED"
            and previous["ip"] == event["ip"]
            and previous["user"] == event["user"]
        ]

        if len(failures) >= FAILED_LOGIN_THRESHOLD:
            print(
                f"WARNING: {event['user']} successfully logged in "
                f"from {event['ip']} after {len(failures)} failed attempts."
            )

print("\nANALYSIS COMPLETE")
print("=" * 50)
