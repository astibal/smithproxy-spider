"""Public legacy logging imports backed by Python's standard logger."""

import json
import logging
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

import addon_log
from addon_log_contract import collect
from addon_modules import compatibility_modules
from addon_native import NativeAddonAdapter
from addon_runtime import AddonGeneration


class AddonLogTests(unittest.IsolatedAsyncioTestCase):
    def test_reference_constants_and_entry_value(self):
        self.assertEqual(addon_log.ALERT, 21)
        self.assertEqual(logging.getLevelName(addon_log.ALERT), 'ALERT')
        self.assertEqual(
            addon_log.LogLevels,
            ['error', 'warn', 'info', 'alert', 'debug'],
        )
        self.assertEqual(
            addon_log.LOG_COLORS,
            {40: 'red', 30: 'yellow', 21: 'magenta'},
        )
        self.assertEqual(
            addon_log.LOGGING_LEVELS_TO_LOGENTRY,
            {40: 'error', 30: 'warn', 20: 'info', 21: 'alert', 10: 'debug'},
        )

        entry = addon_log.LogEntry('hello', 'info')
        self.assertEqual(vars(entry), {'msg': 'hello', 'level': 'info'})
        self.assertEqual(repr(entry), 'LogEntry(hello, info)')
        self.assertEqual(entry, addon_log.LogEntry('hello', 'info'))
        with self.assertRaises(TypeError):
            hash(entry)

        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_log_v12.json').read_text()
        )
        self.assertEqual(
            collect(compatibility_modules()['mitmproxy.log']),
            corpus['logging'],
        )

    def test_module_exports_and_legacy_adapter_use_standard_logging(self):
        modules = compatibility_modules()
        public = modules['mitmproxy.log']
        self.assertIs(public.ALERT, addon_log.ALERT)
        self.assertIs(public.AddLogHook, addon_log.AddLogHook)
        self.assertIs(public.LogEntry, addon_log.LogEntry)
        self.assertIs(modules['mitmproxy'].log, public)

        entry = addon_log.LogEntry('hook message', 'warn')
        event = public.AddLogHook(entry)
        self.assertEqual(event.name, 'add_log')
        self.assertEqual(event.args(), [entry])
        self.assertEqual(repr(event), 'AddLogHook(entry=LogEntry(hook message, warn))')

        self.assertEqual(
            [public.log_tier(name) for name in addon_log.LogLevels],
            [0, 1, 2, 2, 3],
        )
        self.assertIsNone(public.log_tier(logging.INFO))

        legacy = addon_log.Log(None)
        with self.assertWarnsRegex(DeprecationWarning, 'standard Python logging'):
            with self.assertLogs(level='INFO') as records:
                legacy.info('legacy message')
        self.assertIn('legacy message', records.output[0])

        with self.assertLogs(level=addon_log.ALERT) as records:
            legacy('alert message', 'alert')
        self.assertIn('alert message', records.output[0])

    async def test_only_an_explicit_add_log_hook_reaches_the_addon(self):
        source = '''
import logging
from mitmproxy import ctx, log

events = []

def add_log(entry):
    events.append((entry.msg, entry.level, repr(entry)))

def running():
    logging.info("ordinary standard log")
    ctx.log.info("ordinary legacy log")
    ctx.master.addons.trigger(log.AddLogHook(
        log.LogEntry("explicit event", "warn")
    ))
'''
        generation = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        with self.assertWarnsRegex(DeprecationWarning, 'standard Python logging'):
            with self.assertLogs(level='INFO') as records:
                failures = await generation.start()

        self.assertEqual(failures, ())
        self.assertEqual(generation.addon.module.events, [
            ('explicit event', 'warn', 'LogEntry(explicit event, warn)'),
        ])
        self.assertTrue(any(
            'ordinary standard log' in record for record in records.output
        ))
        self.assertTrue(any(
            'ordinary legacy log' in record for record in records.output
        ))
        await generation.close()

    async def test_reference_add_log_delivery_is_explicit_only(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_add_log_v12.json').read_text()
        )
        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(corpus['events'], [{
            'hook': 'add_log',
            'level': 'warn',
            'message': 'spider-add-log-probe:manual-trigger',
            'repr': 'LogEntry(spider-add-log-probe:manual-trigger, warn)',
            'type': 'LogEntry',
        }])

        source = '''
from mitmproxy import ctx, log

events = []

def add_log(entry):
    events.append({
        "hook": "add_log",
        "level": entry.level,
        "message": entry.msg,
        "repr": repr(entry),
        "type": type(entry).__name__,
    })

def running():
    ctx.master.addons.trigger(log.AddLogHook(log.LogEntry(
        "spider-add-log-probe:manual-trigger", "warn"
    )))
'''
        generation = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await generation.start()
        self.assertEqual(generation.addon.module.events, corpus['events'])
        await generation.close()


if __name__ == '__main__':
    unittest.main()
