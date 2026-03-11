"""Tests for pam_oath multi-factor authentication (TOTP second factor)."""

import os
import subprocess
import pytest
import truenas_pypam
from truenas_authenticator import UserPamAuthenticator
from tests.conftest import OATH_SECRET, OATH_SERVICE, TEST_USER, TEST_PASSWORD, setup_oath

WRONG_PASSWORD = 'Dogs'

PAM_PROMPT_ECHO_OFF = truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF
PAMCode = truenas_pypam.PAMCode


@pytest.fixture(autouse=True)
def reset_oath_state():
    """Reset users.oath before each test to clear pam_oath replay-protection state."""
    if os.geteuid() == 0:
        setup_oath()


def current_totp():
    return subprocess.check_output(
        ['oathtool', '--totp', '--base32', OATH_SECRET]
    ).decode().strip()


# ---------------------------------------------------------------------------
# Low-level threaded context tests
# ---------------------------------------------------------------------------

def test_oath_two_round_correct_credentials():
    ctx = truenas_pypam.get_context(user=TEST_USER, service_name=OATH_SERVICE)
    msgs1 = ctx.begin_authentication(timeout=10)        # pam_unix: password prompt
    assert any(m.msg_style == PAM_PROMPT_ECHO_OFF for m in msgs1)
    responses1 = [TEST_PASSWORD if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                  for m in msgs1]

    msgs2 = ctx.continue_authentication(responses1, timeout=10)  # pam_oath: OTP prompt
    assert msgs2 is not None                            # another conversation round
    responses2 = [current_totp() if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                  for m in msgs2]

    result = ctx.continue_authentication(responses2, timeout=10)
    assert result is None                               # PAM_SUCCESS


def test_oath_wrong_password_raises():
    ctx = truenas_pypam.get_context(user=TEST_USER, service_name=OATH_SERVICE)
    msgs = ctx.begin_authentication(timeout=10)
    responses = [WRONG_PASSWORD if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                 for m in msgs]
    with pytest.raises(truenas_pypam.PAMError):
        ctx.continue_authentication(responses, timeout=10)


def test_oath_wrong_otp_raises():
    ctx = truenas_pypam.get_context(user=TEST_USER, service_name=OATH_SERVICE)
    msgs1 = ctx.begin_authentication(timeout=10)
    responses1 = [TEST_PASSWORD if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                  for m in msgs1]
    msgs2 = ctx.continue_authentication(responses1, timeout=10)
    assert msgs2 is not None
    responses2 = ['000000' for _ in msgs2]   # deliberately wrong
    with pytest.raises(truenas_pypam.PAMError):
        ctx.continue_authentication(responses2, timeout=10)


# ---------------------------------------------------------------------------
# High-level UserPamAuthenticator tests
# ---------------------------------------------------------------------------

def test_authenticator_oath_full_flow():
    auth = UserPamAuthenticator(username=TEST_USER, service=OATH_SERVICE,
                                authentication_timeout=10)
    resp1 = auth.auth_init()
    assert resp1.code == PAMCode.PAM_CONV_AGAIN       # password round

    responses1 = [TEST_PASSWORD if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                  for m in resp1.reason]
    resp2 = auth.auth_continue(responses1)
    assert resp2.code == PAMCode.PAM_CONV_AGAIN       # OTP round

    responses2 = [current_totp() if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                  for m in resp2.reason]
    resp3 = auth.auth_continue(responses2)
    assert resp3.code == PAMCode.PAM_SUCCESS
    assert resp3.user_info['pw_name'] == TEST_USER


def test_authenticator_oath_wrong_otp():
    auth = UserPamAuthenticator(username=TEST_USER, service=OATH_SERVICE,
                                authentication_timeout=10)
    resp1 = auth.auth_init()
    responses1 = [TEST_PASSWORD if m.msg_style == PAM_PROMPT_ECHO_OFF else None
                  for m in resp1.reason]
    resp2 = auth.auth_continue(responses1)
    responses2 = ['000000' for _ in resp2.reason]
    resp3 = auth.auth_continue(responses2)
    assert resp3.code == PAMCode.PAM_AUTH_ERR
    assert auth.ctx is None   # cleaned up on failure
