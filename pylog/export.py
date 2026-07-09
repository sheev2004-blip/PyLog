import dataclasses
import json

def export_summary(summary, export_filename):
    with open(export_filename, "w", encoding="utf-8", errors="replace") as file:
        file.write(summary)
    


def export_csv(top_messages, filename, top):
    if top is not None:
        top_messages = top_messages[:top]
    
    with open(filename, "w", encoding="utf-8", errors="replace") as file:
        file.write("Message,Count\n")
        for message, count in top_messages:
            file.write(f"{message},{count}\n")


def export_json(alerts, filename, export_filename):
    output = {
        "version": 1,
        "file": filename,
        "alerts": [dataclasses.asdict(a) for a in alerts]
    }

    with open(export_filename, "w", encoding="utf-8", errors="replace") as file:
        json.dump(output, file, indent=2)

    