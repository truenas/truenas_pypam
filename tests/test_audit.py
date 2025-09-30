"""Test Python auditing hooks for PAM operations."""

import sys
import pytest
import truenas_pypam


# Import test credentials from conftest
from conftest import TEST_USER, TEST_PASSWORD


class AuditCollector:
    """Collect audit events for testing."""
    def __init__(self):
        self.events = []

    def __call__(self, event, args):
        if event.startswith('truenas_pypam.'):
            self.events.append((event, args))

    def clear(self):
        self.events.clear()


@pytest.fixture
def audit_collector():
    """Fixture to collect audit events."""
    collector = AuditCollector()
    sys.addaudithook(collector)
    yield collector
    # Note: audit hooks cannot be removed once added


def test_authenticate_audit(audit_collector):
    """Test that authenticate triggers audit event."""
    def conv_callback(ctx, messages, private_data):
        responses = []
        for msg in messages:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append(TEST_PASSWORD)
            else:
                responses.append(None)
        return responses

    audit_collector.clear()

    ctx = truenas_pypam.get_context(
        service_name='login',
        user=TEST_USER,
        conversation_function=conv_callback
    )

    ctx.authenticate()

    # Check that authenticate was audited
    auth_events = [e for e in audit_collector.events
                   if e[0] == 'truenas_pypam.authenticate']
    assert len(auth_events) == 1
    assert auth_events[0][1] == (TEST_USER,)


def test_acct_mgmt_audit(audit_collector):
    """Test that acct_mgmt triggers audit event."""
    def conv_callback(ctx, messages, private_data):
        responses = []
        for msg in messages:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append(TEST_PASSWORD)
            else:
                responses.append(None)
        return responses

    audit_collector.clear()

    ctx = truenas_pypam.get_context(
        service_name='login',
        user=TEST_USER,
        conversation_function=conv_callback
    )

    ctx.authenticate()
    ctx.acct_mgmt()

    # Check that acct_mgmt was audited
    acct_events = [e for e in audit_collector.events
                   if e[0] == 'truenas_pypam.acct_mgmt']
    assert len(acct_events) == 1
    assert acct_events[0][1] == (TEST_USER,)


def test_session_audit(audit_collector):
    """Test that open_session and close_session trigger audit events."""
    def conv_callback(ctx, messages, private_data):
        responses = []
        for msg in messages:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append(TEST_PASSWORD)
            else:
                responses.append(None)
        return responses

    audit_collector.clear()

    ctx = truenas_pypam.get_context(
        service_name='login',
        user=TEST_USER,
        conversation_function=conv_callback
    )

    ctx.authenticate()
    ctx.acct_mgmt()

    # Open session
    ctx.open_session()

    # Check that open_session was audited
    open_events = [e for e in audit_collector.events
                   if e[0] == 'truenas_pypam.open_session']
    assert len(open_events) == 1
    assert open_events[0][1] == (TEST_USER,)

    # Close session
    ctx.close_session()

    # Check that close_session was audited
    close_events = [e for e in audit_collector.events
                    if e[0] == 'truenas_pypam.close_session']
    assert len(close_events) == 1
    assert close_events[0][1] == (TEST_USER,)


def test_setcred_audit(audit_collector):
    """Test that setcred triggers audit event."""
    def conv_callback(ctx, messages, private_data):
        responses = []
        for msg in messages:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append(TEST_PASSWORD)
            else:
                responses.append(None)
        return responses

    audit_collector.clear()

    ctx = truenas_pypam.get_context(
        service_name='login',
        user=TEST_USER,
        conversation_function=conv_callback
    )

    ctx.authenticate()

    # Set credentials
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED)

    # Check that setcred was audited
    cred_events = [e for e in audit_collector.events
                   if e[0] == 'truenas_pypam.setcred']
    assert len(cred_events) == 1
    # Args should be (user, operation)
    assert cred_events[0][1][0] == TEST_USER
    assert cred_events[0][1][1] == truenas_pypam.CredOp.PAM_ESTABLISH_CRED


def test_multiple_operations_audit(audit_collector):
    """Test that multiple operations each trigger their own audit events."""
    def conv_callback(ctx, messages, private_data):
        responses = []
        for msg in messages:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append(TEST_PASSWORD)
            else:
                responses.append(None)
        return responses

    audit_collector.clear()

    ctx = truenas_pypam.get_context(
        service_name='login',
        user=TEST_USER,
        conversation_function=conv_callback
    )

    # Perform multiple operations
    ctx.authenticate()
    ctx.acct_mgmt()
    ctx.open_session()
    ctx.close_session()

    # Check all events were audited
    event_types = [e[0] for e in audit_collector.events]
    assert 'truenas_pypam.authenticate' in event_types
    assert 'truenas_pypam.acct_mgmt' in event_types
    assert 'truenas_pypam.open_session' in event_types
    assert 'truenas_pypam.close_session' in event_types

    # All should have the same user
    for event, args in audit_collector.events:
        if event.startswith('truenas_pypam.') and event != 'truenas_pypam.setcred':
            assert args == (TEST_USER,)