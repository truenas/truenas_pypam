"""
Pytest configuration and fixtures for truenas_pypam tests.

This module sets up test users needed for testing.
"""
import base64
import os
import pwd
import subprocess
import pytest


TEST_USER = "bob"
TEST_PASSWORD = "Cats"

OATH_SECRET = 'JBSWY3DPEHPK3PXP'   # base32; deterministic across runs
OATH_SERVICE = 'truenas-test-mfa'    # PAM service name


def user_exists(username):
    """Check if a user exists on the system."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def create_test_user():
    """Create the test user 'bob' if it doesn't exist."""
    if user_exists(TEST_USER):
        return True

    # Try to create user (requires root/sudo privileges)
    try:
        # Create user with home directory
        subprocess.run(
            ["useradd", "-m", TEST_USER],
            check=True,
            capture_output=True,
            text=True
        )

        # Set password using chpasswd
        subprocess.run(
            ["chpasswd"],
            input=f"{TEST_USER}:{TEST_PASSWORD}",
            check=True,
            capture_output=True,
            text=True
        )

        print(f"Created test user '{TEST_USER}'")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to create test user: {e.stderr}")
        return False
    except FileNotFoundError:
        print("useradd/chpasswd commands not found")
        return False


def setup_oath():
    """Write /etc/users.oath and /etc/pam.d/truenas-test-mfa."""
    # pam_oath expects the secret in hex; OATH_SECRET is base32
    secret_hex = base64.b32decode(OATH_SECRET).hex()
    with open('/etc/users.oath', 'w') as f:
        f.write(f'HOTP/T30/6 {TEST_USER} - {secret_hex}\n')
    os.chmod('/etc/users.oath', 0o600)

    pam_conf = (
        'auth  requisite  pam_unix.so nodelay\n'
        'auth  required   pam_oath.so usersfile=/etc/users.oath window=10 digits=6\n'
        'account  required  pam_unix.so\n'
    )
    with open(f'/etc/pam.d/{OATH_SERVICE}', 'w') as f:
        f.write(pam_conf)


def pytest_sessionstart(session):
    """
    Called at the start of the test session to ensure test user exists.
    This runs before any tests are collected.
    """
    if not user_exists(TEST_USER):
        if os.geteuid() == 0:  # Running as root
            if not create_test_user():
                pytest.exit(f"Failed to create test user '{TEST_USER}'", 1)
        else:
            pytest.exit(
                f"Test user '{TEST_USER}' does not exist. "
                f"Create it with: sudo useradd -m {TEST_USER} && "
                f"echo '{TEST_USER}:{TEST_PASSWORD}' | sudo chpasswd",
                1
            )

    if os.geteuid() == 0:
        setup_oath()


@pytest.fixture
def test_user_credentials():
    """Provide test user credentials."""
    return {
        "user": TEST_USER,
        "password": TEST_PASSWORD
    }