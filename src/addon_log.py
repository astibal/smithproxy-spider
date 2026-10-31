"""Small public logging facade backed by Python's standard logging module."""

from dataclasses import dataclass
import logging
import warnings

from addon_hooks import Hook


ALERT = 21
LogLevels = ['error', 'warn', 'info', 'alert', 'debug']
LOG_COLORS = {logging.ERROR: 'red', logging.WARNING: 'yellow', ALERT: 'magenta'}
LOGGING_LEVELS_TO_LOGENTRY = {
    logging.ERROR: 'error',
    logging.WARNING: 'warn',
    logging.INFO: 'info',
    ALERT: 'alert',
    logging.DEBUG: 'debug',
}

logging.addLevelName(ALERT, 'ALERT')


@dataclass
class LogEntry:
    """One legacy event-log record retained for addon import compatibility."""

    msg: str
    level: str

    def __repr__(self):
        return f'LogEntry({self.msg}, {self.level})'


@dataclass
class AddLogHook(Hook):
    """Public event value used by legacy event-log consumers."""

    entry: LogEntry


def log_tier(level):
    """Map a legacy log-level name to its display tier."""
    return {
        'error': 0,
        'warn': 1,
        'alert': 2,
        'info': 2,
        'debug': 3,
    }.get(level)


class Log:
    """Deprecated ctx.log adapter that emits standard Python log records."""

    def __init__(self, master):
        # Keep the public constructor; Spider does not run a second event log.
        self.master = master

    def __call__(self, text, level='info'):
        levels = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warn': logging.WARNING,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'alert': ALERT,
        }
        logging.log(levels.get(level, level), text)

    def _write(self, name, text):
        warnings.warn(
            f"mitmproxy's ctx.log.{name}() is deprecated. "
            'Please use the standard Python logging module instead.',
            DeprecationWarning,
            stacklevel=3,
        )
        self(text, name)

    def debug(self, text):
        self._write('debug', text)

    def info(self, text):
        self._write('info', text)

    def alert(self, text):
        self._write('alert', text)

    def warn(self, text):
        self._write('warn', text)

    def error(self, text):
        self._write('error', text)
