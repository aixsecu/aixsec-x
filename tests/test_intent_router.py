import pytest

from intent_router import classify, extract_targets, transition_action
from scope import ScopePolicy


class ClassifierChat:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def __call__(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return {'content': self.payload, 'tool_calls': []}


@pytest.mark.parametrize(('text', 'expected'), [
    ('Phân tích [https://b.com](https://b.com)', ['https://b.com']),
    ('Scan b.com', ['https://b.com']),
    ('Phân tích https\\://b.com/path', ['https://b.com/path']),
    ('Audit http://10.0.0.8:8080', ['http://10.0.0.8:8080']),
    ('Scan 10.0.0.0/24', ['10.0.0.0/24']),
])
def test_target_extractor_handles_markdown_bare_and_escaped_urls(text, expected):
    assert extract_targets(text) == expected


def test_target_extractor_does_not_treat_email_as_target():
    assert extract_targets('Email security@example.com for help') == []


@pytest.mark.parametrize('text', [
    'Scan b.com', 'Alalyze b.com', 'Analyze and find vulnerabilities https://b.com',
    'Phân tích https://b.com',
])
def test_high_precision_rules_skip_ai(text):
    chat = ClassifierChat('{}')
    decision = classify(text, chat, {})
    assert decision.intent == 'scan_target'
    assert decision.source == 'rule'
    assert decision.confidence >= .85
    assert chat.calls == []


def test_explicit_negation_never_switches_scope():
    decision = classify('Không scan b.com', ClassifierChat('{}'), {})
    assert decision.intent == 'exclude_target'
    assert transition_action(decision, ScopePolicy(['https://a.com'])) == 'stay'


def test_ai_classifies_arbitrary_language_but_cannot_invent_target():
    chat = ClassifierChat(
        '{"intent":"scan_target","confidence":0.93,"reason":"explicit Japanese request",'
        '"targets":["https://invented.example"]}')
    decision = classify('b.com の脆弱性を調べて', chat, {'model': 'test'})
    assert decision.intent == 'scan_target'
    assert decision.targets == ('https://b.com',)
    assert decision.source == 'ai'
    assert chat.calls[0][1]['json_mode'] is True
    assert chat.calls[0][1]['tools'] == []


def test_ai_discussion_does_not_switch_and_medium_confidence_asks():
    policy = ScopePolicy(['https://a.com'])
    discuss = classify('What do you know about b.com?', ClassifierChat(
        '{"intent":"discuss_target","confidence":0.97,"reason":"question"}'), {})
    assert transition_action(discuss, policy) == 'stay'
    uncertain = classify('Maybe b.com?', ClassifierChat(
        '{"intent":"scan_target","confidence":0.7,"reason":"ambiguous"}'), {})
    assert transition_action(uncertain, policy) == 'confirm'


def test_malformed_ai_output_fails_closed_without_scope_switch():
    decision = classify('看看 b.com', ClassifierChat('not-json'), {})
    assert decision.intent == 'unclear'
    assert decision.confidence == 0
    assert transition_action(decision, ScopePolicy(['https://a.com'])) == 'stay'


def test_in_scope_scan_does_not_create_new_session():
    decision = classify('Scan api.a.com', ClassifierChat('{}'), {})
    assert transition_action(decision, ScopePolicy(['https://a.com'])) == 'stay'
