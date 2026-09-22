SEVERITY_LEVELS = {
    "critical": {
        "label": "Critical",
        "score": 4
    },
    "high": {
        "label": "High",
        "score": 3
    },
    "medium": {
        "label": "Medium",
        "score": 2
    },
    "low": {
        "label": "Low",
        "score": 1
    },
    "info": {
        "label": "Info",
        "score": 0
    }
}


def normalize_severity(severity):
    severity = severity.lower().strip()

    if severity not in SEVERITY_LEVELS:
        return "Info"

    return SEVERITY_LEVELS[severity]["label"]