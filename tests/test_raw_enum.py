"""Tests for truenas_pypam enum functionality."""

import pytest
import truenas_pypam


def test_pam_code_enum_exists():
    """Test that PAMCode enum is available."""
    assert hasattr(truenas_pypam, 'PAMCode')
    assert truenas_pypam.PAMCode is not None


@pytest.mark.parametrize("member_name", [
    'PAM_SUCCESS',
    'PAM_OPEN_ERR',
    'PAM_SYMBOL_ERR',
    'PAM_SERVICE_ERR',
    'PAM_SYSTEM_ERR',
    'PAM_BUF_ERR',
    'PAM_PERM_DENIED',
    'PAM_AUTH_ERR',
    'PAM_CRED_INSUFFICIENT',
    'PAM_AUTHINFO_UNAVAIL',
    'PAM_USER_UNKNOWN',
    'PAM_MAXTRIES',
    'PAM_NEW_AUTHTOK_REQD',
    'PAM_ACCT_EXPIRED',
    'PAM_SESSION_ERR',
    'PAM_CRED_UNAVAIL',
    'PAM_CRED_EXPIRED',
    'PAM_CRED_ERR',
    'PAM_NO_MODULE_DATA',
    'PAM_CONV_ERR',
    'PAM_AUTHTOK_ERR',
    'PAM_AUTHTOK_RECOVERY_ERR',
    'PAM_AUTHTOK_LOCK_BUSY',
    'PAM_AUTHTOK_DISABLE_AGING',
    'PAM_TRY_AGAIN',
    'PAM_IGNORE',
    'PAM_ABORT',
    'PAM_AUTHTOK_EXPIRED',
    'PAM_MODULE_UNKNOWN',
    'PAM_BAD_ITEM',
    'PAM_CONV_AGAIN',
    'PAM_INCOMPLETE',
])
def test_pam_code_enum_members(member_name):
    """Test PAMCode enum has expected members."""
    assert hasattr(truenas_pypam.PAMCode, member_name)


@pytest.mark.parametrize("member_name,expected_value", [
    ('PAM_SUCCESS', 0),
    ('PAM_AUTH_ERR', 7),
    ('PAM_USER_UNKNOWN', 10),
])
def test_pam_code_enum_values(member_name, expected_value):
    """Test PAMCode enum members have correct values."""
    member = getattr(truenas_pypam.PAMCode, member_name)
    assert member == expected_value


def test_pam_code_enum_is_int_enum():
    """Test PAMCode enum members are IntEnum instances."""
    success = truenas_pypam.PAMCode.PAM_SUCCESS
    assert isinstance(success, int)
    assert success == 0
    assert str(success) == '0'


def test_msg_style_enum_exists():
    """Test that MSGStyle enum is available."""
    assert hasattr(truenas_pypam, 'MSGStyle')
    assert truenas_pypam.MSGStyle is not None


@pytest.mark.parametrize("member_name", [
    'PAM_PROMPT_ECHO_OFF',
    'PAM_PROMPT_ECHO_ON',
    'PAM_ERROR_MSG',
    'PAM_TEXT_INFO',
])
def test_msg_style_enum_members(member_name):
    """Test MSGStyle enum has expected members."""
    assert hasattr(truenas_pypam.MSGStyle, member_name)


@pytest.mark.parametrize("member_name,expected_value", [
    ('PAM_PROMPT_ECHO_OFF', 1),
    ('PAM_PROMPT_ECHO_ON', 2),
    ('PAM_ERROR_MSG', 3),
    ('PAM_TEXT_INFO', 4),
])
def test_msg_style_enum_values(member_name, expected_value):
    """Test MSGStyle enum members have correct values."""
    member = getattr(truenas_pypam.MSGStyle, member_name)
    assert member == expected_value


def test_cred_op_enum_exists():
    """Test that CredOp enum is available."""
    assert hasattr(truenas_pypam, 'CredOp')
    assert truenas_pypam.CredOp is not None


@pytest.mark.parametrize("member_name", [
    'PAM_ESTABLISH_CRED',
    'PAM_DELETE_CRED',
    'PAM_REINITIALIZE_CRED',
    'PAM_REFRESH_CRED',
])
def test_cred_op_enum_members(member_name):
    """Test CredOp enum has expected members."""
    assert hasattr(truenas_pypam.CredOp, member_name)


@pytest.mark.parametrize("member_name,expected_value", [
    ('PAM_ESTABLISH_CRED', 2),
    ('PAM_DELETE_CRED', 4),
    ('PAM_REINITIALIZE_CRED', 8),
    ('PAM_REFRESH_CRED', 16),
])
def test_cred_op_enum_values(member_name, expected_value):
    """Test CredOp enum members have correct values."""
    member = getattr(truenas_pypam.CredOp, member_name)
    assert member == expected_value


@pytest.mark.parametrize("enum_type,expected_name", [
    (truenas_pypam.PAMCode, 'truenas_pypam.PAMCode'),
    (truenas_pypam.MSGStyle, 'truenas_pypam.MSGStyle'),
    (truenas_pypam.CredOp, 'truenas_pypam.CredOp'),
])
def test_enum_name_attributes(enum_type, expected_name):
    """Test enum name attributes are correct."""
    assert enum_type.__name__ == expected_name


def test_enum_member_comparison():
    """Test enum members can be compared properly."""
    success1 = truenas_pypam.PAMCode.PAM_SUCCESS
    success2 = truenas_pypam.PAMCode.PAM_SUCCESS
    auth_err = truenas_pypam.PAMCode.PAM_AUTH_ERR

    assert success1 == success2
    assert success1 != auth_err
    assert success1 == 0
    assert auth_err == 7


def test_enum_member_hashing():
    """Test enum members can be used as dictionary keys."""
    test_dict = {
        truenas_pypam.PAMCode.PAM_SUCCESS: 'success',
        truenas_pypam.PAMCode.PAM_AUTH_ERR: 'auth_error',
    }

    assert test_dict[truenas_pypam.PAMCode.PAM_SUCCESS] == 'success'
    assert test_dict[truenas_pypam.PAMCode.PAM_AUTH_ERR] == 'auth_error'
