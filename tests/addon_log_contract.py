"""Public logging observations shared by reference and adapter tests."""


def collect(log):
    entry = log.LogEntry("hook message", "warn")
    event = log.AddLogHook(entry)
    levels = ["error", "warn", "info", "alert", "debug", "unknown", 20]
    return {
        "alert": log.ALERT,
        "levels": list(log.LogLevels),
        "colors": {str(key): value for key, value in log.LOG_COLORS.items()},
        "python_levels": {
            str(key): value
            for key, value in log.LOGGING_LEVELS_TO_LOGENTRY.items()
        },
        "entry": {
            "state": vars(entry),
            "repr": repr(entry),
        },
        "add_log_hook": {
            "name": event.name,
            "args_are_entry": event.args() == [entry],
            "repr": repr(event),
        },
        "tiers": {
            repr(level): log.log_tier(level)
            for level in levels
        },
    }
