"""
Pytest configuration and fixtures for truenas_pypam tests.

This module sets up test users needed for testing.
"""
import os
import pwd
import subprocess
import pytest


TEST_USER = "bob"
TEST_PASSWORD = "Cats"


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


@pytest.fixture
def test_user_credentials():
    """Provide test user credentials."""
    return {
        "user": TEST_USER,
        "password": TEST_PASSWORD
    }