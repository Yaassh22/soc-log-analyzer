def parse_log(log):
    parts = log.split()

    event = {}

    # First two pieces are the date and time
    event["date"] = parts[0]
    event["time"] = parts[1]

    # Everything after the timestamp is key=value data
    for part in parts[2:]:
        if "=" in part:
            key, value = part.split("=", 1)
            event[key] = value

    return event


event_alerts = {
    "4624": "Successful Login",
    "4625": "Failed Login",
    "4688": "Process Creation"
}


def main():
    failed_logins = {}
    threshold_user = {}

    with open("logs.txt", "r") as file:
        for line in file:
            line = line.strip()

            if line:
                event = parse_log(line)
                event_id = event["EventID"]

                # Failed login detection
                if event_id == "4625":
                    user = event.get("User", "-")

                    if user not in failed_logins:
                        failed_logins[user] = 1
                    else:
                        failed_logins[user] += 1

                    if failed_logins[user] == 3:
                        threshold_user[user] = True

                        print(
                            "ALERT: User", user,
                            "has", failed_logins[user],
                            "failed login attempts"
                        )

                # PowerShell correlation
                if event_id == "4688":
                    process = event.get("NewProcess", "-")
                    user = event.get("User", "-")
                    time = event.get("time", "-")
                    source_ip = event.get("SourceIP", "-")

                    if process.lower() == "powershell.exe" and user in threshold_user:
                        print(
                            "CORRELATED ALERT:",
                            "| User:", user,
                            "| Time:", time,
                            "| Process:", process,
                            "| Source IP:", source_ip
                        )

                # Normal event output
                print(
                    "Event:", event_alerts.get(event_id, "Unknown event ID"),
                    "| Time:", event.get("time", "-"),
                    "| User:", event.get("User", "-"),
                    "| Source IP:", event.get("SourceIP", "-")
                )


if __name__ == "__main__":
    main()
