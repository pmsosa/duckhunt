#!/usr/bin/env python
"""
######################################################
#                   DuckHunter                       #
#                 Pedro M. Sosa                      #
# Tool to prevent getting attacked by a rubberducky! #
######################################################
"""

import importlib.machinery
import importlib.util
import json
import logging
import math
import statistics
import sys
import time
from collections import deque
from logging.handlers import RotatingFileHandler

import pythoncom

try:
    # Python 2 + pyHook
    import pyHook  # type: ignore
except ImportError:
    # Python 3 + pyWinhook
    import pyWinhook as pyHook  # type: ignore

import win32ui


def load_config(config_path='duckhunt.conf'):
    """Dynamically load configuration from duckhunt.conf."""
    loader = importlib.machinery.SourceFileLoader("duckhunt_config", config_path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    config_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_module)
    return config_module


def as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "y", "on")
    return default


def as_int(value, default, minimum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and parsed < minimum:
        return minimum
    return parsed


def as_float(value, default, minimum=None):
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and parsed < minimum:
        return minimum
    return parsed


def as_csv_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value).split(",")
    return [str(item).strip() for item in items if str(item).strip()]


def normalize_policy(raw_policy):
    policy = str(raw_policy or "normal").strip().lower()
    if policy == "log":
        return "logonly"
    if policy in ("paranoid", "normal", "sneaky", "logonly"):
        return policy
    return "normal"


def normalize_key_name(key_name):
    return str(key_name or "").strip().replace(" ", "").upper()


def parse_pattern_signatures(value):
    signatures = []
    if value is None:
        return signatures

    if isinstance(value, (list, tuple)):
        raw_groups = value
    else:
        raw_groups = str(value).split(";")

    for group in raw_groups:
        if isinstance(group, (list, tuple)):
            tokens = [normalize_key_name(token) for token in group]
        else:
            tokens = [normalize_key_name(token) for token in str(group).split(",")]
        tokens = [token for token in tokens if token]
        if len(tokens) >= 2:
            signatures.append(tuple(tokens))
    return signatures


def parse_window_threshold_overrides(value):
    """Parse 'window:threshold' pairs separated by ';'."""
    overrides = []
    if value is None:
        return overrides

    if isinstance(value, (list, tuple)):
        raw_items = value
    else:
        raw_items = str(value).split(";")

    for item in raw_items:
        chunk = str(item).strip()
        if not chunk or ":" not in chunk:
            continue
        name, threshold_text = chunk.split(":", 1)
        token = name.strip().lower()
        threshold = as_int(threshold_text.strip(), default=-1, minimum=1)
        if token and threshold > 0:
            overrides.append((token, threshold))
    return overrides


def normalize_command_fragment(value):
    return " ".join(str(value or "").lower().split())


def parse_command_fragments(value):
    fragments = []
    if value is None:
        return fragments

    if isinstance(value, (list, tuple, set)):
        raw_items = value
    else:
        raw_items = str(value).split(";")

    for item in raw_items:
        fragment = normalize_command_fragment(item)
        if fragment:
            fragments.append(fragment)
    return fragments


def configure_logging(filename, level_name, max_bytes, backup_count):
    logger = logging.getLogger()
    logger.handlers = []
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if max_bytes > 0:
        handler = RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=backup_count)
    else:
        handler = logging.FileHandler(filename)

    handler.setFormatter(formatter)
    logger.addHandler(handler)


config = load_config()

DEFAULT_COMMAND_FRAGMENT_SIGNATURES = (
    "powershell -enc",
    "powershell /enc",
    "encodedcommand",
    "frombase64string",
    "invoke-webrequest",
    "downloadstring",
    "start-process",
    "cmd.exe /c",
    "curl http",
    "iwr http",
    "irm http",
    "certutil",
    "bitsadmin",
    "mshta",
    "rundll32",
    "reg add",
    "schtasks",
    "net user",
    "add-mppreference",
    "set-mppreference",
)
DEFAULT_SENSITIVE_WINDOWS = "command prompt,windows powershell,powershell,terminal,cmd.exe,run,registry editor"

THRESHOLD = as_int(getattr(config, "threshold", 30), 30, minimum=1)
HISTORY_SIZE = as_int(getattr(config, "size", 25), 25, minimum=3)
POLICY = normalize_policy(getattr(config, "policy", "normal"))
PASSWORD = str(getattr(config, "password", ""))
ALLOW_AUTO_TYPE = as_bool(getattr(config, "allow_auto_type_software", True), default=True)
RANDDROP_INTERVAL = as_int(getattr(config, "randdrop", 6), 6, minimum=1)
LOG_FILENAME = str(getattr(config, "filename", "log.txt"))
BLACKLIST = [item.lower() for item in as_csv_list(getattr(config, "blacklist", ""))]
WHITELIST = [item.lower() for item in as_csv_list(getattr(config, "whitelist", ""))]
LOG_LEVEL = str(getattr(config, "log_level", "INFO")).upper()
DEBUG = as_bool(getattr(config, "debug", False), default=False)

# Advanced options
NORMAL_LOCKOUT_MS = as_int(getattr(config, "normal_lockout_ms", 1200), 1200, minimum=0)
RAPID_BURST_INTERVAL_MS = as_int(getattr(config, "rapid_burst_interval_ms", 12), 12, minimum=1)
RAPID_BURST_COUNT = as_int(getattr(config, "rapid_burst_count", 8), 8, minimum=0)
INJECTED_BURST_COUNT = as_int(getattr(config, "injected_burst_count", 0), 0, minimum=0)

# Optional signature + adaptive detection
PATTERN_SIGNATURES = parse_pattern_signatures(getattr(config, "pattern_signatures", ""))
KEY_BUFFER_SIZE = as_int(getattr(config, "key_buffer_size", 18), 18, minimum=4)
COMMAND_FRAGMENT_DETECTION = as_bool(getattr(config, "command_fragment_detection", True), default=True)
COMMAND_FRAGMENT_SIGNATURES = parse_command_fragments(
    getattr(config, "command_fragment_signatures", DEFAULT_COMMAND_FRAGMENT_SIGNATURES)
)
COMMAND_FRAGMENT_BUFFER_SIZE = as_int(getattr(config, "command_fragment_buffer_size", 220), 220, minimum=40)
RISK_SCORE_ENABLED = as_bool(getattr(config, "risk_score_enabled", True), default=True)
RISK_SCORE_THRESHOLD = as_int(getattr(config, "risk_score_threshold", 80), 80, minimum=1)
SENSITIVE_WINDOWS = [
    item.lower() for item in as_csv_list(getattr(config, "sensitive_windows", DEFAULT_SENSITIVE_WINDOWS))
]
ADAPTIVE_THRESHOLD_ENABLED = as_bool(getattr(config, "adaptive_threshold_enabled", False), default=False)
ADAPTIVE_MIN_SAMPLES = as_int(getattr(config, "adaptive_min_samples", 40), 40, minimum=5)
ADAPTIVE_SAMPLE_SIZE = as_int(getattr(config, "adaptive_sample_size", 140), 140, minimum=ADAPTIVE_MIN_SAMPLES)
ADAPTIVE_MULTIPLIER = as_float(getattr(config, "adaptive_multiplier", 0.35), 0.35, minimum=0.05)
ADAPTIVE_FLOOR_MS = as_int(getattr(config, "adaptive_floor_ms", 12), 12, minimum=1)
ADAPTIVE_CEILING_MS = as_int(getattr(config, "adaptive_ceiling_ms", 90), 90, minimum=ADAPTIVE_FLOOR_MS)
WINDOW_THRESHOLD_OVERRIDES = parse_window_threshold_overrides(getattr(config, "window_threshold_overrides", ""))

# Low-variance detector for machine-like key bursts.
LOW_VARIANCE_DETECTION = as_bool(getattr(config, "low_variance_detection", True), default=True)
LOW_VARIANCE_STDDEV_MS = as_float(getattr(config, "low_variance_stddev_ms", 2.5), 2.5, minimum=0.1)
LOW_VARIANCE_SPEED_CEILING_MS = as_int(getattr(config, "low_variance_speed_ceiling_ms", 55), 55, minimum=1)
LOW_VARIANCE_STREAK_COUNT = as_int(getattr(config, "low_variance_streak_count", 6), 6, minimum=1)

# Timing entropy catches highly repetitive cadence even when basic stddev checks miss it.
TIMING_ENTROPY_DETECTION = as_bool(getattr(config, "timing_entropy_detection", True), default=True)
TIMING_ENTROPY_WINDOW = as_int(getattr(config, "timing_entropy_window", 12), 12, minimum=4)
TIMING_ENTROPY_MIN_SAMPLES = min(
    TIMING_ENTROPY_WINDOW,
    as_int(getattr(config, "timing_entropy_min_samples", 10), 10, minimum=4),
)
TIMING_ENTROPY_BIN_MS = as_int(getattr(config, "timing_entropy_bin_ms", 5), 5, minimum=1)
TIMING_ENTROPY_THRESHOLD = as_float(getattr(config, "timing_entropy_threshold", 1.25), 1.25, minimum=0.0)
TIMING_ENTROPY_SPEED_CEILING_MS = as_int(getattr(config, "timing_entropy_speed_ceiling_ms", 90), 90, minimum=1)
TIMING_ENTROPY_STREAK_COUNT = as_int(getattr(config, "timing_entropy_streak_count", 2), 2, minimum=1)

# Optional runtime status export
STATUS_FILENAME = str(getattr(config, "status_filename", ""))
STATUS_FLUSH_INTERVAL = as_int(getattr(config, "status_flush_interval", 250), 250, minimum=1)
INCIDENT_JSON_FILENAME = str(getattr(config, "incident_json_filename", "")).strip()
INCIDENT_JSON_INCLUDE_WINDOW = as_bool(getattr(config, "incident_json_include_window", True), default=True)
LOG_MAX_BYTES = as_int(getattr(config, "log_max_bytes", 1048576), 1048576, minimum=0)
LOG_BACKUP_COUNT = as_int(getattr(config, "log_backup_count", 5), 5, minimum=1)

NORMAL_LOCKOUT_BACKOFF_ENABLED = as_bool(getattr(config, "normal_lockout_backoff_enabled", True), default=True)
NORMAL_LOCKOUT_BACKOFF_WINDOW_MS = as_int(
    getattr(config, "normal_lockout_backoff_window_ms", 10000), 10000, minimum=100
)
NORMAL_LOCKOUT_BACKOFF_MULTIPLIER = as_float(
    getattr(config, "normal_lockout_backoff_multiplier", 1.6), 1.6, minimum=1.0
)
NORMAL_LOCKOUT_MAX_MS = as_int(getattr(config, "normal_lockout_max_ms", 8000), 8000, minimum=NORMAL_LOCKOUT_MS)

RISK_SESSION_ENABLED = as_bool(getattr(config, "risk_session_enabled", True), default=True)
RISK_SESSION_WINDOW_MS = as_int(getattr(config, "risk_session_window_ms", 1800), 1800, minimum=100)
RISK_SESSION_THRESHOLD = as_int(getattr(config, "risk_session_threshold", 130), 130, minimum=1)

# Warmup mode: avoid blocking on speed heuristics during startup calibration.
WARMUP_EVENTS = as_int(getattr(config, "warmup_events", 0), 0, minimum=0)
WARMUP_ACTION = str(getattr(config, "warmup_action", "logonly")).strip().lower()
if WARMUP_ACTION not in ("logonly", "enforce"):
    WARMUP_ACTION = "logonly"

configure_logging(LOG_FILENAME, LOG_LEVEL, LOG_MAX_BYTES, LOG_BACKUP_COUNT)


class DuckHunter:
    def __init__(self):
        self.policy = POLICY
        self.password = PASSWORD
        self.allow_auto = ALLOW_AUTO_TYPE
        self.randdrop_interval = RANDDROP_INTERVAL
        self.threshold = THRESHOLD
        self.history_size = HISTORY_SIZE
        self.blacklist = BLACKLIST
        self.whitelist = WHITELIST
        self.normal_lockout_ms = NORMAL_LOCKOUT_MS
        self.rapid_burst_interval = RAPID_BURST_INTERVAL_MS
        self.rapid_burst_count = RAPID_BURST_COUNT
        self.injected_burst_count = INJECTED_BURST_COUNT
        self.pattern_signatures = PATTERN_SIGNATURES
        self.key_buffer = deque(maxlen=KEY_BUFFER_SIZE)
        self.command_fragment_detection = COMMAND_FRAGMENT_DETECTION
        self.command_fragment_signatures = COMMAND_FRAGMENT_SIGNATURES
        self.command_fragment_buffer = deque(maxlen=COMMAND_FRAGMENT_BUFFER_SIZE)
        self.command_context_window = ""
        self.risk_score_enabled = RISK_SCORE_ENABLED
        self.risk_score_threshold = RISK_SCORE_THRESHOLD
        self.sensitive_windows = SENSITIVE_WINDOWS
        self.window_threshold_overrides = WINDOW_THRESHOLD_OVERRIDES

        self.adaptive_threshold_enabled = ADAPTIVE_THRESHOLD_ENABLED
        self.adaptive_min_samples = ADAPTIVE_MIN_SAMPLES
        self.adaptive_multiplier = ADAPTIVE_MULTIPLIER
        self.adaptive_floor_ms = ADAPTIVE_FLOOR_MS
        self.adaptive_ceiling_ms = ADAPTIVE_CEILING_MS
        self.baseline_intervals = deque(maxlen=ADAPTIVE_SAMPLE_SIZE)
        self.effective_threshold = self.threshold
        self.active_threshold = self.threshold

        self.low_variance_detection = LOW_VARIANCE_DETECTION
        self.low_variance_stddev = LOW_VARIANCE_STDDEV_MS
        self.low_variance_speed_ceiling = LOW_VARIANCE_SPEED_CEILING_MS
        self.low_variance_streak_count = LOW_VARIANCE_STREAK_COUNT
        self.timing_entropy_detection = TIMING_ENTROPY_DETECTION
        self.timing_entropy_min_samples = TIMING_ENTROPY_MIN_SAMPLES
        self.timing_entropy_bin_ms = TIMING_ENTROPY_BIN_MS
        self.timing_entropy_threshold = TIMING_ENTROPY_THRESHOLD
        self.timing_entropy_speed_ceiling = TIMING_ENTROPY_SPEED_CEILING_MS
        self.timing_entropy_streak_count = TIMING_ENTROPY_STREAK_COUNT
        self.entropy_intervals = deque(maxlen=TIMING_ENTROPY_WINDOW)
        self.timing_entropy = 0.0

        self.status_filename = STATUS_FILENAME.strip()
        self.status_flush_interval = STATUS_FLUSH_INTERVAL
        self.incident_json_filename = INCIDENT_JSON_FILENAME
        self.incident_json_include_window = INCIDENT_JSON_INCLUDE_WINDOW
        self.normal_lockout_backoff_enabled = NORMAL_LOCKOUT_BACKOFF_ENABLED
        self.normal_lockout_backoff_window_ms = NORMAL_LOCKOUT_BACKOFF_WINDOW_MS
        self.normal_lockout_backoff_multiplier = NORMAL_LOCKOUT_BACKOFF_MULTIPLIER
        self.normal_lockout_max_ms = NORMAL_LOCKOUT_MAX_MS
        self.risk_session_enabled = RISK_SESSION_ENABLED
        self.risk_session_window_ms = RISK_SESSION_WINDOW_MS
        self.risk_session_threshold = RISK_SESSION_THRESHOLD
        self.risk_events = deque()
        self.events_since_flush = 0
        self.warmup_events = WARMUP_EVENTS
        self.warmup_action = WARMUP_ACTION

        self.debug = DEBUG

        self.history = [self.threshold + 1] * self.history_size
        self.history_index = 0
        self.interval_count = 0
        self.history_total = float(sum(self.history))
        self.history_square_total = float(sum(value * value for value in self.history))
        self.average_speed = self.history_total / self.history_size
        self.interval_stddev = 0.0

        self.previous_time = -1
        self.is_intrusion = False
        self.password_counter = 0
        self.last_window = ""
        self.randdrop_counter = 0
        self.normal_block_until = 0
        self.current_normal_lockout_ms = self.normal_lockout_ms
        self.recent_intrusion_times = deque()
        self.rapid_burst_counter = 0
        self.injected_burst_counter = 0
        self.low_variance_counter = 0
        self.low_entropy_counter = 0

        self.total_events = 0
        self.allowed_events = 0
        self.blocked_events = 0
        self.intrusion_count = 0
        self.last_intrusion_reason = ""
        self.last_intrusion_window = ""
        self.last_intrusion_key = ""
        self.last_intrusion_at_ms = 0
        self.last_risk_score = 0
        self.last_risk_reasons = []
        self.last_risk_session_score = 0
        self.last_risk_session_reasons = []

        self.hook_manager = pyHook.HookManager()
        self.hook_manager.KeyDown = self.on_key_down

    def debug_log(self, message, *args):
        if self.debug:
            logging.debug(message, *args)

    def is_window_whitelisted(self, window_name):
        lowered = (window_name or "").lower()
        return any(token in lowered for token in self.whitelist)

    def is_window_blacklisted(self, window_name):
        lowered = (window_name or "").lower()
        return any(token in lowered for token in self.blacklist)

    def is_sensitive_window(self, window_name):
        lowered = (window_name or "").lower()
        return any(token in lowered for token in self.sensitive_windows)

    def get_window_threshold_override(self, window_name):
        lowered = (window_name or "").lower()
        for token, threshold in self.window_threshold_overrides:
            if token in lowered:
                return threshold
        return None

    def update_interval_metrics(self, interval):
        self.interval_count += 1
        old_value = self.history[self.history_index]
        self.history[self.history_index] = interval
        self.history_index = (self.history_index + 1) % self.history_size
        self.history_total += interval - old_value
        self.average_speed = self.history_total / float(self.history_size)
        mean = self.average_speed
        self.history_square_total += (interval * interval) - (old_value * old_value)
        variance = (self.history_square_total / float(self.history_size)) - (mean * mean)
        if variance < 0:
            variance = 0
        self.interval_stddev = variance ** 0.5

    def update_entropy_metrics(self, interval):
        if not self.timing_entropy_detection or interval <= 0:
            return

        self.entropy_intervals.append(interval)
        if len(self.entropy_intervals) < self.timing_entropy_min_samples:
            self.timing_entropy = 0.0
            self.low_entropy_counter = 0
            return

        bins = {}
        for value in self.entropy_intervals:
            bucket = int(value / float(self.timing_entropy_bin_ms))
            bins[bucket] = bins.get(bucket, 0) + 1

        total = float(len(self.entropy_intervals))
        entropy = 0.0
        for count in bins.values():
            probability = count / total
            entropy -= probability * math.log(probability, 2)

        self.timing_entropy = entropy
        recent_median = statistics.median(self.entropy_intervals)
        if recent_median <= self.timing_entropy_speed_ceiling and entropy <= self.timing_entropy_threshold:
            self.low_entropy_counter += 1
        else:
            self.low_entropy_counter = 0

    def compute_effective_threshold(self):
        if not self.adaptive_threshold_enabled:
            self.effective_threshold = self.threshold
            return self.effective_threshold

        if len(self.baseline_intervals) < self.adaptive_min_samples:
            self.effective_threshold = self.threshold
            return self.effective_threshold

        baseline_median = statistics.median(self.baseline_intervals)
        adaptive_value = baseline_median * self.adaptive_multiplier
        adaptive_value = max(self.adaptive_floor_ms, min(self.adaptive_ceiling_ms, adaptive_value))

        blended_threshold = (self.threshold + adaptive_value) / 2.0
        self.effective_threshold = int(round(max(self.threshold, blended_threshold)))
        return self.effective_threshold

    def remember_clean_interval(self, interval, event):
        if event.Injected:
            return
        if interval <= 0:
            return
        self.baseline_intervals.append(interval)

    def log_attack(self, event):
        window_name = event.WindowName or "<unknown>"
        if self.last_window != window_name:
            logging.info("\n[ %s ]", window_name)
            self.last_window = window_name
        try:
            if 32 < event.Ascii < 127:
                logging.info("%s", chr(event.Ascii))
            else:
                logging.info("[%s]", event.Key)
        except Exception as exc:
            logging.exception("Error logging key: %s", exc)

    def log_intrusion(self, event, reason):
        logging.warning(
            "Intrusion detected reason=%s policy=%s avg_interval_ms=%.2f threshold_ms=%d "
            "effective_threshold_ms=%d active_threshold_ms=%d stddev_ms=%.2f "
            "rapid_streak=%d injected_streak=%d low_variance_streak=%d "
            "entropy=%.3f low_entropy_streak=%d risk_score=%d session_risk_score=%d "
            "risk_reasons=%s normal_lockout_ms=%d window=%r key=%r injected=%r",
            reason,
            self.policy,
            self.average_speed,
            self.threshold,
            self.effective_threshold,
            self.active_threshold,
            self.interval_stddev,
            self.rapid_burst_counter,
            self.injected_burst_counter,
            self.low_variance_counter,
            self.timing_entropy,
            self.low_entropy_counter,
            self.last_risk_score,
            self.last_risk_session_score,
            "|".join(self.last_risk_reasons),
            self.current_normal_lockout_ms,
            event.WindowName,
            event.Key,
            event.Injected,
        )

    def pattern_match_reason(self):
        if not self.pattern_signatures:
            return ""

        buffer_list = list(self.key_buffer)
        for signature in self.pattern_signatures:
            sig_len = len(signature)
            if len(buffer_list) >= sig_len and tuple(buffer_list[-sig_len:]) == signature:
                return "pattern_match:{}".format("->".join(signature))
        return ""

    def update_command_context(self, event):
        if not self.command_fragment_detection:
            return

        window_name = (getattr(event, "WindowName", "") or "").lower()
        if window_name != self.command_context_window:
            self.command_fragment_buffer.clear()
            self.command_context_window = window_name

        key_name = normalize_key_name(getattr(event, "Key", ""))
        ascii_code = getattr(event, "Ascii", 0)
        try:
            ascii_code = int(ascii_code)
        except (TypeError, ValueError):
            ascii_code = 0

        if 32 <= ascii_code < 127:
            self.command_fragment_buffer.append(chr(ascii_code).lower())
        elif key_name in ("RETURN", "ENTER", "TAB"):
            self.command_fragment_buffer.append(" ")
        elif key_name in ("BACK", "BACKSPACE") and self.command_fragment_buffer:
            self.command_fragment_buffer.pop()

    def command_fragment_match_reason(self):
        if not self.command_fragment_detection or not self.command_fragment_signatures:
            return ""

        context = normalize_command_fragment("".join(self.command_fragment_buffer))
        if not context:
            return ""

        for fragment in self.command_fragment_signatures:
            if fragment in context:
                safe_fragment = fragment.replace(" ", "_")[:48]
                return "command_fragment:{}".format(safe_fragment)
        return ""

    def risk_increment_for_reason(self, reason):
        if reason == "blacklisted_window":
            return 100
        if reason.startswith("pattern_match"):
            return 80
        if reason.startswith("command_fragment"):
            return 50
        if reason == "injected_burst":
            return 70
        if reason == "rapid_burst":
            return 50
        if reason == "low_variance_burst":
            return 45
        if reason == "low_entropy_timing":
            return 45
        if reason == "average_speed":
            return 35
        if reason == "injected_event":
            return 20
        if reason in ("rapid_sequence", "low_variance_sequence"):
            return 15
        if reason == "near_threshold_speed":
            return 0
        return 0

    def update_risk_session(self, event_time, reasons):
        if not self.risk_session_enabled:
            self.last_risk_session_score = 0
            self.last_risk_session_reasons = []
            return ""

        increment = sum(self.risk_increment_for_reason(reason) for reason in reasons)
        if increment > 0:
            self.risk_events.append((event_time, increment, tuple(reasons[:4])))

        cutoff = event_time - self.risk_session_window_ms
        while self.risk_events and self.risk_events[0][0] < cutoff:
            self.risk_events.popleft()

        total = sum(item[1] for item in self.risk_events)
        merged_reasons = []
        for _, _, item_reasons in self.risk_events:
            for reason in item_reasons:
                if reason != "sensitive_window" and reason not in merged_reasons:
                    merged_reasons.append(reason)

        self.last_risk_session_score = total
        self.last_risk_session_reasons = merged_reasons[:6]

        if total >= self.risk_session_threshold:
            label = "+".join(self.last_risk_session_reasons[:3]) or "accumulated_evidence"
            return "risk_session:{}".format(label)
        return ""

    def score_event_risk(self, event, pattern_reason, command_fragment_reason):
        score = [0]
        reasons = []

        def add(points, reason):
            score[0] += points
            reasons.append(reason)

        window_name = getattr(event, "WindowName", "") or ""
        if self.is_window_blacklisted(window_name):
            add(100, "blacklisted_window")
        if self.is_sensitive_window(window_name):
            add(25, "sensitive_window")
        if command_fragment_reason:
            add(55, command_fragment_reason)
        if pattern_reason:
            add(80, pattern_reason)
        if getattr(event, "Injected", False):
            add(35, "injected_event")

        if self.low_entropy_counter >= self.timing_entropy_streak_count:
            add(45, "low_entropy_timing")

        if self.rapid_burst_count > 0:
            if self.rapid_burst_counter >= self.rapid_burst_count:
                add(55, "rapid_burst")
            elif self.rapid_burst_counter >= max(3, self.rapid_burst_count // 2):
                add(25, "rapid_sequence")

        if self.injected_burst_count > 0 and self.injected_burst_counter >= self.injected_burst_count:
            add(70, "injected_burst")

        if self.low_variance_counter >= self.low_variance_streak_count:
            add(50, "low_variance_burst")
        elif self.low_variance_counter >= max(3, self.low_variance_streak_count // 2):
            add(20, "low_variance_sequence")

        if self.average_speed < self.active_threshold:
            add(45, "average_speed")
        elif self.average_speed < (self.active_threshold * 1.35):
            add(20, "near_threshold_speed")

        self.last_risk_score = score[0]
        self.last_risk_reasons = reasons[:6]
        session_reason = self.update_risk_session(int(getattr(event, "Time", 0)), reasons)

        if self.risk_score_enabled and score[0] >= self.risk_score_threshold:
            return "risk_score:{}".format("+".join(reasons[:3]))
        return session_reason

    def in_warmup_phase(self):
        return self.warmup_events > 0 and self.total_events <= self.warmup_events

    def should_enforce_during_warmup(self, reason):
        if reason == "blacklisted_window":
            return True
        if reason.startswith("pattern_match"):
            return True
        if reason.startswith(("risk_score", "risk_session")):
            return any(
                item.startswith(("blacklisted_window", "pattern_match", "command_fragment"))
                for item in self.last_risk_reasons + self.last_risk_session_reasons
            )
        return False

    def handle_warmup_intrusion(self, event, reason):
        warmup_reason = "warmup_{}".format(reason)
        self.intrusion_count += 1
        self.last_intrusion_reason = warmup_reason
        self.last_intrusion_window = event.WindowName or ""
        self.last_intrusion_key = event.Key or ""
        self.last_intrusion_at_ms = int(time.time() * 1000)
        self.log_intrusion(event, warmup_reason)
        self.log_attack(event)
        return True

    def trigger_intrusion(self, event, reason):
        if (
            self.in_warmup_phase() and
            self.warmup_action == "logonly" and
            not self.should_enforce_during_warmup(reason)
        ):
            result = self.handle_warmup_intrusion(event, reason)
        else:
            result = self.handle_intrusion(event, reason)

        self.write_incident_json(event, result)
        self.record_decision(result, force_status=True)
        return result

    def record_decision(self, allowed, force_status=False):
        if allowed:
            self.allowed_events += 1
        else:
            self.blocked_events += 1
        self.flush_status(force=force_status)

    def flush_status(self, force=False):
        if not self.status_filename:
            return
        self.events_since_flush += 1
        if not force and self.events_since_flush < self.status_flush_interval:
            return

        payload = self.get_status_snapshot()
        payload["timestamp_epoch_ms"] = int(time.time() * 1000)

        try:
            with open(self.status_filename, "w") as status_file:
                json.dump(payload, status_file, sort_keys=True)
        except Exception as exc:
            logging.exception("Unable to write status file %r: %s", self.status_filename, exc)

        self.events_since_flush = 0

    def get_status_snapshot(self):
        return {
            "policy": self.policy,
            "threshold_ms": self.threshold,
            "effective_threshold_ms": self.effective_threshold,
            "active_threshold_ms": self.active_threshold,
            "average_speed_ms": round(self.average_speed, 2),
            "interval_stddev_ms": round(self.interval_stddev, 3),
            "total_events": self.total_events,
            "allowed_events": self.allowed_events,
            "blocked_events": self.blocked_events,
            "intrusion_count": self.intrusion_count,
            "last_intrusion_reason": self.last_intrusion_reason,
            "last_intrusion_window": self.last_intrusion_window,
            "last_intrusion_key": self.last_intrusion_key,
            "adaptive_threshold_enabled": self.adaptive_threshold_enabled,
            "adaptive_samples": len(self.baseline_intervals),
            "low_variance_detection": self.low_variance_detection,
            "low_variance_streak": self.low_variance_counter,
            "timing_entropy_detection": self.timing_entropy_detection,
            "timing_entropy": round(self.timing_entropy, 3),
            "low_entropy_streak": self.low_entropy_counter,
            "command_fragment_detection": self.command_fragment_detection,
            "risk_score_enabled": self.risk_score_enabled,
            "risk_score_threshold": self.risk_score_threshold,
            "last_risk_score": self.last_risk_score,
            "last_risk_reasons": list(self.last_risk_reasons),
            "risk_session_enabled": self.risk_session_enabled,
            "risk_session_threshold": self.risk_session_threshold,
            "last_risk_session_score": self.last_risk_session_score,
            "last_risk_session_reasons": list(self.last_risk_session_reasons),
            "current_normal_lockout_ms": self.current_normal_lockout_ms,
            "warmup_events": self.warmup_events,
            "warmup_remaining_events": max(0, self.warmup_events - self.total_events),
        }

    def compute_normal_lockout_ms(self, event_time):
        if not self.normal_lockout_backoff_enabled or self.normal_lockout_ms <= 0:
            self.current_normal_lockout_ms = self.normal_lockout_ms
            return self.current_normal_lockout_ms

        cutoff = event_time - self.normal_lockout_backoff_window_ms
        while self.recent_intrusion_times and self.recent_intrusion_times[0] < cutoff:
            self.recent_intrusion_times.popleft()
        self.recent_intrusion_times.append(event_time)

        streak = max(1, len(self.recent_intrusion_times))
        duration = self.normal_lockout_ms * (self.normal_lockout_backoff_multiplier ** (streak - 1))
        self.current_normal_lockout_ms = int(min(self.normal_lockout_max_ms, max(self.normal_lockout_ms, duration)))
        return self.current_normal_lockout_ms

    def write_incident_json(self, event, allowed):
        if not self.incident_json_filename:
            return

        payload = {
            "timestamp_epoch_ms": int(time.time() * 1000),
            "event_time_ms": int(getattr(event, "Time", 0)),
            "policy": self.policy,
            "action": "allowed" if allowed else "blocked",
            "reason": self.last_intrusion_reason,
            "key": getattr(event, "Key", ""),
            "injected": bool(getattr(event, "Injected", False)),
            "average_speed_ms": round(self.average_speed, 2),
            "interval_stddev_ms": round(self.interval_stddev, 3),
            "timing_entropy": round(self.timing_entropy, 3),
            "threshold_ms": self.threshold,
            "active_threshold_ms": self.active_threshold,
            "risk_score": self.last_risk_score,
            "risk_reasons": list(self.last_risk_reasons),
            "risk_session_score": self.last_risk_session_score,
            "risk_session_reasons": list(self.last_risk_session_reasons),
            "rapid_streak": self.rapid_burst_counter,
            "injected_streak": self.injected_burst_counter,
            "low_variance_streak": self.low_variance_counter,
            "low_entropy_streak": self.low_entropy_counter,
            "normal_lockout_ms": self.current_normal_lockout_ms,
        }
        if self.incident_json_include_window:
            payload["window"] = getattr(event, "WindowName", "")

        try:
            with open(self.incident_json_filename, "a") as incident_file:
                json.dump(payload, incident_file, sort_keys=True)
                incident_file.write("\n")
        except Exception as exc:
            logging.exception("Unable to write incident JSON file %r: %s", self.incident_json_filename, exc)

    def handle_intrusion(self, event, reason):
        was_intrusion = self.is_intrusion
        self.is_intrusion = True
        self.intrusion_count += 1
        self.last_intrusion_reason = reason
        self.last_intrusion_window = event.WindowName or ""
        self.last_intrusion_key = event.Key or ""
        self.last_intrusion_at_ms = int(time.time() * 1000)

        if self.policy == "normal":
            lockout_ms = self.compute_normal_lockout_ms(int(event.Time))
        else:
            lockout_ms = self.current_normal_lockout_ms

        self.log_intrusion(event, reason)

        if self.policy == "normal":
            self.normal_block_until = int(event.Time) + lockout_ms

        if self.policy == "paranoid":
            if not was_intrusion:
                win32ui.MessageBox(
                    "Key injection detected!\nCheck your ports or running programs.\n"
                    "Enter your password to unlock the keyboard.",
                    "KeyInjection Detected",
                    4096
                )
            return False

        if self.policy == "sneaky":
            self.randdrop_counter += 1
            should_drop = (self.randdrop_counter % self.randdrop_interval == 0)
            if should_drop:
                self.log_attack(event)
            return not should_drop

        if self.policy == "logonly":
            self.log_attack(event)
            return True

        self.log_attack(event)
        return False

    def handle_paranoid_unlock(self, event):
        self.log_attack(event)
        try:
            char = chr(event.Ascii)
        except Exception:
            char = ''

        if (
            self.password and
            self.password_counter < len(self.password) and
            self.password[self.password_counter] == char
        ):
            self.password_counter += 1
            if self.password_counter == len(self.password):
                win32ui.MessageBox(
                    "Correct Password! Keyboard unlocked.",
                    "KeyInjection Detected",
                    4096
                )
                self.is_intrusion = False
                self.password_counter = 0
        else:
            self.password_counter = 0
        return False

    def on_key_down(self, event):
        window_name = event.WindowName or ""
        event_time = int(event.Time)

        self.total_events += 1

        if self.is_window_whitelisted(window_name):
            self.previous_time = event_time
            self.rapid_burst_counter = 0
            self.injected_burst_counter = 0
            self.record_decision(True)
            return True

        if self.policy == "normal" and event_time < self.normal_block_until:
            self.record_decision(False)
            return False

        if self.policy == "paranoid" and self.is_intrusion:
            result = self.handle_paranoid_unlock(event)
            self.record_decision(result)
            return result

        if self.previous_time == -1:
            key_name = normalize_key_name(event.Key)
            if key_name:
                self.key_buffer.append(key_name)
            self.update_command_context(event)
            self.previous_time = event_time
            self.record_decision(True)
            return True

        interval = max(0, event_time - self.previous_time)
        self.previous_time = event_time
        self.update_interval_metrics(interval)
        self.update_entropy_metrics(interval)

        if interval <= self.rapid_burst_interval:
            self.rapid_burst_counter += 1
        else:
            self.rapid_burst_counter = 0

        if event.Injected:
            self.injected_burst_counter += 1
        else:
            self.injected_burst_counter = 0

        key_name = normalize_key_name(event.Key)
        if key_name:
            self.key_buffer.append(key_name)
        self.update_command_context(event)

        self.effective_threshold = self.compute_effective_threshold()
        threshold_override = self.get_window_threshold_override(window_name)
        self.active_threshold = threshold_override if threshold_override is not None else self.effective_threshold

        if (
            self.low_variance_detection and
            self.average_speed <= self.low_variance_speed_ceiling and
            self.interval_stddev <= self.low_variance_stddev
        ):
            self.low_variance_counter += 1
        else:
            self.low_variance_counter = 0

        pattern_reason = self.pattern_match_reason()
        command_fragment_reason = self.command_fragment_match_reason()

        if (
            event.Injected and
            self.allow_auto and
            not self.is_window_blacklisted(window_name) and
            (self.injected_burst_count <= 0 or self.injected_burst_counter < self.injected_burst_count) and
            not pattern_reason and
            not command_fragment_reason
        ):
            self.record_decision(True)
            return True

        risk_reason = self.score_event_risk(event, pattern_reason, command_fragment_reason)

        self.debug_log(
            "event key=%r injected=%r interval=%d avg=%.2f stddev=%.3f "
            "rapid=%d injected_streak=%d low_variance=%d effective=%d active=%d "
            "entropy=%.3f low_entropy=%d risk=%d session_risk=%d risk_reasons=%s",
            event.Key,
            event.Injected,
            interval,
            self.average_speed,
            self.interval_stddev,
            self.rapid_burst_counter,
            self.injected_burst_counter,
            self.low_variance_counter,
            self.effective_threshold,
            self.active_threshold,
            self.timing_entropy,
            self.low_entropy_counter,
            self.last_risk_score,
            self.last_risk_session_score,
            "|".join(self.last_risk_reasons),
        )

        if self.is_window_blacklisted(window_name):
            return self.trigger_intrusion(event, "blacklisted_window")

        if self.rapid_burst_count > 0 and self.rapid_burst_counter >= self.rapid_burst_count:
            return self.trigger_intrusion(event, "rapid_burst")

        if self.injected_burst_count > 0 and self.injected_burst_counter >= self.injected_burst_count:
            return self.trigger_intrusion(event, "injected_burst")

        if self.low_variance_counter >= self.low_variance_streak_count:
            return self.trigger_intrusion(event, "low_variance_burst")

        if pattern_reason:
            return self.trigger_intrusion(event, pattern_reason)

        if risk_reason:
            return self.trigger_intrusion(event, risk_reason)

        if self.average_speed < self.active_threshold:
            return self.trigger_intrusion(event, "average_speed")

        self.is_intrusion = False
        self.remember_clean_interval(interval, event)
        self.record_decision(True)
        return True

    def run(self):
        self.hook_manager.HookKeyboard()
        self.flush_status(force=True)
        try:
            pythoncom.PumpMessages()
        except Exception as exc:
            logging.exception("An error occurred in the message pump: %s", exc)
            sys.exit(1)
        finally:
            self.flush_status(force=True)


if __name__ == '__main__':
    duckhunter = DuckHunter()
    try:
        duckhunter.run()
    except KeyboardInterrupt:
        print("DuckHunter terminated by user.")
    except Exception as ex:
        logging.exception("DuckHunter encountered an error: %s", ex)
