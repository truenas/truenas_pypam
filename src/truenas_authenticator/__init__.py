"""
TrueNAS Authenticator - High-level PAM authentication API

This module provides a Pythonic interface to PAM authentication
using the truenas_pypam extension.
"""

from .authenticator import (
    # Main authenticator classes
    UserPamAuthenticator,
    SimpleAuthenticator,

    # Enums and data classes
    AuthenticatorStage,
    AccountFlag,
    AuthenticatorState,
    AuthenticatorResponse,
)

__all__ = [
    'UserPamAuthenticator',
    'ApiKeyPamAuthenticator',
    'SimpleAuthenticator',
    'AuthenticatorStage',
    'AccountFlag',
    'AuthenticatorState',
    'AuthenticatorResponse',
]

__version__ = '0.1.0'
