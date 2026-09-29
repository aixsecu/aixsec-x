"""Multilingual scan-intent routing with deterministic scope transitions."""
from dataclasses import dataclass
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit


INTENTS = {
    'scan_target', 'continue_current_scan', 'discuss_target',
    'exclude_target', 'compare_targets', 'unclear',
}


@dataclass(frozen=True)
class IntentDecision:
    intent: str
    targets: tuple[str, ...]
    confidence: float
    source: str
    reason: str = ''


def _canonical_target(raw):
    value = raw.strip().strip('[]()<>').rstrip('.,;:!?')
    value = value.replace('\\:', ':').replace('\\/', '/')
    if not value:
        return None
    if '://' not in value and '/' in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    if '://' not in value:
        value = 'https://' + value
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if parsed.scheme not in ('http', 'https') or not host:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if '.' not in host or not re.fullmatch(r'[A-Za-z0-9.-]+', host):
                return None
        netloc = host.lower()
        if parsed.port:
            netloc += f':{parsed.port}'
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or '',
                           parsed.query, ''))
    except (ValueError, UnicodeError):
        return None


def extract_targets(text):
    """Extract only targets literally present in text; never infer a hostname."""
    cleaned = text.replace('\\:', ':').replace('\\/', '/')
    candidates = []
    candidates += re.findall(r'\[[^\]]*\]\((https?://[^\s)]+)\)', cleaned,
                             flags=re.IGNORECASE)
    candidates += re.findall(r'https?://[^\s\]\[()<>{}"\']+', cleaned,
                             flags=re.IGNORECASE)
    # Bare DNS names and IPv4 hosts, optionally with port/path. Email domains
    # are excluded by the negative lookbehind.
    candidates += re.findall(
        r'(?<![@\w./-])(?:www\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}'
        r'(?::\d{1,5})?(?:/[A-Za-z0-9._~:/?#[\]@!$&\'()*+,;=%-]*)?', cleaned)
    candidates += re.findall(
        r'(?<![\w./])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[0-9]{1,2})?', cleaned)
    result = []
    for candidate in candidates:
        target = _canonical_target(candidate)
        if target and target not in result:
            result.append(target)
    return result


def _rule_decision(text, targets):
    normalized = text.casefold()
    negative = re.search(
        r'\b(?:do not|don\'t|never|không|khong|đừng|dung|no)\s+'
        r'(?:scan|quét|quet|analy[sz]e|phân tích|phan tich|audit|pentest)', normalized)
    if negative:
        return IntentDecision('exclude_target', tuple(targets), .99, 'rule',
                              'explicit negation')
    # High-precision fast path only. The AI classifier handles other languages,
    # indirect wording and the long tail of spelling mistakes.
    action = re.search(
        r'\b(?:scan|sacn|quét|quet|phân tích|phan tich|analy[sz]e|analize|alalyze|'
        r'audit|pentest|tìm lỗ hổng|tim lo hong|kiểm tra|kiem tra)\b', normalized)
    if action:
        return IntentDecision('scan_target', tuple(targets), .98, 'rule',
                              'explicit scan action')
    return None


def _json_object(content):
    text = str(content or '').strip()
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text, flags=re.IGNORECASE)
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        match = re.search(r'\{.*\}', text, flags=re.DOTALL)
        if not match:
            return {}
        try:
            value = json.loads(match.group(0))
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def classify(text, chat, config):
    targets = extract_targets(text)
    if not targets:
        return IntentDecision('unclear', (), 0.0, 'extractor',
                              'no literal target found')
    ruled = _rule_decision(text, targets)
    if ruled:
        return ruled
    prompt = (
        'Classify the user message for a web-security terminal. Return JSON only: '
        '{"intent":"scan_target|continue_current_scan|discuss_target|exclude_target|'
        'compare_targets|unclear","confidence":0.0,"reason":"short"}. '
        'A URL being mentioned does not by itself mean scan authorization. '
        'Understand any language and common typos. Do not return or infer targets.\n\n'
        f'User message:\n{text[:2000]}')
    try:
        classifier_config = dict(config)
        classifier_config.update(stream=False, think=False, temperature=0.0,
                                 num_predict=120)
        response = chat([
            {'role': 'system', 'content': 'You are a strict intent classifier, not an agent.'},
            {'role': 'user', 'content': prompt},
        ], tools=[], config=classifier_config, json_mode=True)
        data = _json_object(response.get('content'))
        intent = data.get('intent') if data.get('intent') in INTENTS else 'unclear'
        confidence = min(1.0, max(0.0, float(data.get('confidence', 0))))
        reason = str(data.get('reason', ''))[:240]
        return IntentDecision(intent, tuple(targets), confidence, 'ai', reason)
    except (TypeError, ValueError, KeyError) as exc:
        return IntentDecision('unclear', tuple(targets), 0.0, 'ai',
                              f'classifier error: {exc}')


def transition_action(decision, policy):
    """Return switch, confirm, stay or none without granting authorization."""
    if not decision.targets:
        return 'none'
    if decision.intent in ('exclude_target', 'discuss_target', 'continue_current_scan'):
        return 'stay'
    if decision.intent == 'compare_targets':
        return 'confirm'
    if decision.intent == 'scan_target':
        if all(policy.in_scope(target) for target in decision.targets):
            return 'stay'
        if decision.confidence >= .85:
            return 'switch'
        if decision.confidence >= .55:
            return 'confirm'
    return 'confirm' if decision.confidence >= .55 else 'stay'
