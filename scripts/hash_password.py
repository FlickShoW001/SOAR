"""Generate a SOAR scrypt password verifier without echoing the password."""

from getpass import getpass

from main import _hash_password


if __name__ == "__main__":
    first = getpass("Password: ")
    second = getpass("Confirm password: ")
    if first != second or not first:
        raise SystemExit("Passwords do not match or are empty")
    print(_hash_password(first))
