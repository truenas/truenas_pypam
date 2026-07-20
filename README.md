# TrueNAS PyPAM Client

Python bindings for PAM (Pluggable Authentication Modules) with a high-level authentication API designed for TrueNAS.

## Overview

This package provides:
- **truenas_pypam**: Low-level C extension module providing direct Python bindings to PAM
- **truenas_authenticator**: High-level Pythonic API for authentication workflows

## Features

- Serialized access to the PAM handle (see [Thread safety](#thread-safety))
- Native C-threaded PAM conversation — no Python threading overhead
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
pip install -e .
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

`UserPamAuthenticator` drives PAM via the C extension's native threaded mode.
Each `auth_init()` / `auth_continue()` call suspends the internal PAM thread
at a conversation boundary and returns the pending messages to the caller.
No Python threads or queues are involved.

```python
from truenas_authenticator import UserPamAuthenticator
import truenas_pypam

# Create authenticator
auth = UserPamAuthenticator(username='bob', service='login')

# Initialize authentication — starts the C auth thread internally
resp = auth.auth_init()

# Handle conversation (e.g., password prompt)
if resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN:
    # resp.reason is a tuple of PAM message objects
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
    auth.login()

    # ... do work ...

    # Close session
    auth.logout()
```

### Simple Authentication

For basic username/password authentication without conversation handling:

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

For direct PAM access with an explicit conversation callback:

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

# Create PAM context with a conversation function
ctx = truenas_pypam.get_context(
    service_name='login',
    user='bob',
    conversation_function=conversation_callback
)

# Authenticate (conversation_callback is called synchronously)
ctx.authenticate()

# Check account
ctx.acct_mgmt()

# Open session
ctx.open_session()

# Close session
ctx.close_session()
```

When `get_context()` is called **without** a `conversation_function`, the
context operates in native threaded mode and must use `begin_authentication()`
/ `continue_authentication()` instead of `authenticate()`.  `UserPamAuthenticator`
handles this automatically.

## API Reference

### High-Level Classes

#### UserPamAuthenticator
Main authenticator class for multi-step PAM authentication with conversation
support.  Uses the C extension's native threaded mode internally — dropping
Python-level threading machinery entirely.

**Parameters:**
- `username` (str): Username to authenticate
- `service` (str): PAM service name (default: `'login'`)
- `authentication_timeout` (int): Per-step timeout in seconds (default: 10)
- `rhost` (str, optional): Remote host
- `ruser` (str, optional): Remote user
- `fail_delay` (int, optional): Fail delay in microseconds
- `pam_env` (dict, optional): Extra PAM environment variables to set

**Methods:**
- `auth_init()`: Start authentication; returns `PAM_CONV_AGAIN` with messages or `PAM_SUCCESS`
- `auth_continue(responses)`: Supply responses to a pending conversation round
- `account_management()`: Run `pam_acct_mgmt()` after successful authentication
- `login()`: Open a PAM session
- `logout()`: Close the PAM session and clean up
- `end()`: Abort any in-progress authentication and reset state (C auth thread
  is cancelled via dealloc of the context object)

#### SimpleAuthenticator
Simplified authenticator for single-step username/password authentication.
Wraps the synchronous `authenticate()` path with a built-in conversation
callback — no threading involved.

**Parameters:**
- `username` (str): Username to authenticate
- `password` (str): User password
- `service` (str): PAM service name (default: `'login'`)

**Methods:**
- `authenticate_simple()`: Perform authentication, returns `True`/`False`

### Low-Level Functions

#### get_context()
Create a PAM context for authentication.

**Parameters:**
- `service_name` (str): PAM service configuration to use
- `user` (str): Username to authenticate
- `conversation_function` (callable, optional): Callback for PAM conversation;
  omit to create a native threaded context for use with
  `begin_authentication()` / `continue_authentication()`
- `conversation_private_data` (any): Data passed to conversation callback
- `confdir` (str, optional): PAM configuration directory
- `rhost` (str, optional): Remote host
- `ruser` (str, optional): Remote user
- `fail_delay` (int, optional): Fail delay in microseconds

### Enums and Constants

#### PAMCode
PAM return codes (e.g., `PAM_SUCCESS`, `PAM_AUTH_ERR`, `PAM_CONV_AGAIN`)

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

```bash
# Run all tests
pytest tests/

# Run authenticator tests only
pytest tests/test_authenticator.py -v
```

## Development

### Building the Extension

```bash
# Build and install in editable mode
pip install -e .

# Run tests
pytest tests/
```

### Project Structure

```
truenas_pypam/
|-- src/
|   |-- ext/                    C extension source files
|   |   |-- truenas_pypam.c     Main module entry point
|   |   |-- py_auth.c           authenticate() for callback-based contexts
|   |   |-- py_auth_thread.c    begin/continue_authentication() + pthread machinery
|   |   |-- py_acct_mgmt.c      pam_acct_mgmt() binding
|   |   |-- py_ctx.c            Context creation and lifecycle
|   |   |-- py_conv.c           Conversation callback plumbing
|   |   |-- py_chauthtok.c      Password change binding
|   |   |-- py_cred.c           Credential management binding
|   |   |-- py_env.c            PAM environment binding
|   |   |-- py_error.c          PAMError exception type
|   |   |-- py_session.c        Session open/close binding
|   |   `-- truenas_pypam.h     Shared internal header
|   `-- truenas_authenticator/  High-level Python API
|       |-- __init__.py
|       `-- authenticator.py
|-- tests/                      Test suite
|-- examples/                   Example scripts
|-- debian/                     Debian packaging
`-- setup.py                    Build configuration
```

## Thread safety

A `pam_handle_t` is not a thread-safe object. libpam does no internal locking,
PAM transactions are sequential by contract, and its entry points reject calls
made while a transaction is already in progress on the handle. Nothing this
library does can change that, so **a context must be driven by one thread at a
time.** Give each concurrent authentication its own context.

What the library does provide is narrower: a per-context mutex serializes calls
into libpam so that concurrent access cannot corrupt the handle. That matters
even for a caller that never shares a context, because `begin_authentication()`
spawns an internal thread which sits inside `pam_authenticate()` for the
duration of the exchange. While that thread is running module code the handle
belongs to it, and other calls on the context block until it parks in the
conversation or finishes.

A PAM module may itself be unsafe to run concurrently, in which case a single
context per thread is not enough and the consumer needs one lock covering all
contexts. Prefer not to configure such modules.

## Security Considerations

- This module requires appropriate PAM configuration on the system
- Authentication operations require appropriate privileges
- Credentials should never be logged or stored in plain text
- PAM sessions should always be properly closed to avoid resource leaks
- Deallocating a PAM context while authentication is in progress cancels
  the C auth thread cleanly before freeing resources

### Python Auditing

The extension module implements Python auditing hooks for security-sensitive
operations.  The following events are audited:

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

## License

LGPL-3.0-or-later - See LICENSE file for details.
