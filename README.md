# TrueNAS PyPAM Client

Python bindings for PAM (Pluggable Authentication Modules) with a high-level authentication API designed for TrueNAS.

## Overview

This package provides:
- **truenas_pypam**: Low-level C extension module providing direct Python bindings to PAM
- **truenas_authenticator**: High-level Pythonic API for authentication workflows

## Features

- Thread-safe PAM authentication with pthread locks
- Asynchronous conversation handling via threading and queues
- Session management (open/close)
- Account management and validation
- Support for various PAM services (login, sshd, sudo, etc.)
- Password change functionality
- Environment variable management
- Credential management

## Installation

### From Source

```bash
# Install build dependencies
apt-get install libpam0g-dev libbsd-dev python3-dev

# Build and install
python3 setup.py build
python3 setup.py install
```

### Debian Package

```bash
# Build the Debian package
dpkg-buildpackage -us -uc

# Install the package
dpkg -i ../python3-truenas-pypam_*.deb
```

## Usage

### High-Level API (Recommended)

The high-level API provides a clean, Pythonic interface for authentication:

```python
from truenas_authenticator import UserPamAuthenticator
import truenas_pypam

# Create authenticator
auth = UserPamAuthenticator(username='bob', service='login')

# Initialize authentication
resp = auth.auth_init()

# Handle conversation (e.g., password prompt)
if resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN:
    # Provide responses to PAM prompts
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append('password123')  # Password prompt
        else:
            responses.append(None)

    # Continue authentication with responses
    resp = auth.auth_continue(responses)

# Check if authentication succeeded
if resp.code == truenas_pypam.PAMCode.PAM_SUCCESS:
    print("Authentication successful!")

    # Open session
    auth.login('session123')

    # ... do work ...

    # Close session
    auth.logout()
```

### Simple Authentication

For basic username/password authentication:

```python
from truenas_authenticator import SimpleAuthenticator

auth = SimpleAuthenticator(
    username='bob',
    password='password123',
    service='login'
)

if auth.authenticate_simple():
    print("Authentication successful!")
else:
    print("Authentication failed!")
```

### Low-Level API

For direct PAM access:

```python
import truenas_pypam

def conversation_callback(ctx, messages, private_data):
    """Handle PAM conversation"""
    responses = []
    for msg in messages:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append('password123')
        else:
            responses.append(None)
    return responses

# Create PAM context
ctx = truenas_pypam.get_context(
    service_name='login',
    user='bob',
    conversation_function=conversation_callback
)

# Authenticate
ctx.authenticate()

# Check account
ctx.acct_mgmt()

# Open session
ctx.open_session()

# Close session
ctx.close_session()
```

## API Reference

### High-Level Classes

#### UserPamAuthenticator
Main authenticator class for PAM authentication with conversation support.

**Parameters:**
- `username` (str): Username to authenticate
- `service` (str): PAM service name (default: 'login')
- `authentication_timeout` (int): Timeout in seconds (default: 10)
- `rhost` (str, optional): Remote host
- `ruser` (str, optional): Remote user
- `fail_delay` (int, optional): Fail delay in microseconds

**Methods:**
- `auth_init()`: Start authentication, returns conversation messages
- `auth_continue(responses)`: Continue with responses to conversation
- `login(session_id)`: Open PAM session
- `logout()`: Close PAM session and cleanup
- `end()`: Force cleanup of resources

#### SimpleAuthenticator
Simplified authenticator for basic username/password authentication.

**Parameters:**
- `username` (str): Username to authenticate
- `password` (str): User password
- `service` (str): PAM service name (default: 'login')

**Methods:**
- `authenticate_simple()`: Perform authentication, returns True/False

### Low-Level Functions

#### get_context()
Create a PAM context for authentication.

**Parameters:**
- `service_name` (str): PAM service configuration to use
- `user` (str): Username to authenticate
- `conversation_function` (callable): Callback for PAM conversation
- `conversation_private_data` (any): Data passed to conversation callback
- `confdir` (str, optional): PAM configuration directory
- `rhost` (str, optional): Remote host
- `ruser` (str, optional): Remote user
- `fail_delay` (int, optional): Fail delay in microseconds

### Enums and Constants

#### PAMCode
PAM return codes (e.g., PAM_SUCCESS, PAM_AUTH_ERR, PAM_CONV_AGAIN)

#### MSGStyle
PAM message styles:
- `PAM_PROMPT_ECHO_OFF`: Password prompt (no echo)
- `PAM_PROMPT_ECHO_ON`: Username prompt (with echo)
- `PAM_ERROR_MSG`: Error message
- `PAM_TEXT_INFO`: Informational text

#### AuthenticatorStage
Authentication workflow stages:
- `START`: Initial state
- `AUTH`: Authentication in progress
- `LOGIN`: Authenticated, ready to open session
- `LOGOUT`: Session open, ready to close
- `OPEN_SESSION`: Opening session
- `CLOSE_SESSION`: Closing session

## Testing

Run the test suite:

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_authenticator.py

# Run with verbose output
pytest -v tests/
```

## Development

### Building the Extension

```bash
# Build in-place for development
python3 setup.py build_ext --inplace

# Run tests
pytest tests/
```

### Project Structure

```
truenas_pypam_client/
├── src/
│   ├── ext/                  # C extension source files
│   │   ├── truenas_pypam.c   # Main module
│   │   ├── py_auth.c         # Authentication functions
│   │   ├── py_ctx.c          # Context management
│   │   ├── py_conv.c         # Conversation handling
│   │   └── ...
│   └── truenas_authenticator/ # High-level Python API
│       ├── __init__.py
│       └── authenticator.py
├── tests/                    # Test suite
├── examples/                 # Example scripts
├── debian/                   # Debian packaging
└── setup.py                 # Build configuration
```

## Security Considerations

- This module requires appropriate PAM configuration on the system
- Authentication operations require appropriate privileges
- Credentials should never be logged or stored in plain text
- The module uses pthread locks for thread safety
- PAM sessions should always be properly closed to avoid resource leaks

### Python Auditing

The extension module implements Python auditing hooks for security-sensitive operations. The following events are audited:

- `truenas_pypam.authenticate` - Authentication attempts
- `truenas_pypam.acct_mgmt` - Account management checks
- `truenas_pypam.open_session` - PAM session opening
- `truenas_pypam.close_session` - PAM session closing
- `truenas_pypam.chauthtok` - Password change attempts
- `truenas_pypam.setcred` - Credential establishment/deletion

You can monitor these events using `sys.addaudithook()`:

```python
import sys

def audit_hook(event, args):
    if event.startswith('truenas_pypam.'):
        print(f"PAM operation: {event}, user: {args[0]}")

sys.addaudithook(audit_hook)
```

This provides visibility into authentication operations for security monitoring and compliance purposes.

## License

LGPL-3.0-or-later - See LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows the existing style
- New features include tests
- Documentation is updated

## Support

For issues and questions, please file an issue on the project repository.