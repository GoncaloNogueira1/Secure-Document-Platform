from . import utils
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHash

ph = PasswordHasher(type=Type.ID)


def get_user_by_username(cur, username):
    cur.execute(
        """
        SELECT id, username, password, is_disabled, is_admin,
            two_factor_secret, COALESCE(two_factor_enabled, FALSE)
        FROM users WHERE username = %s
        """,
        (username,),
    )
    return cur.fetchone()


def create_user(cur, username, password, is_admin=False):
    password_hash = ph.hash(password)
    return create_user_hashed(cur, username, password_hash, is_admin=is_admin)


def create_user_with_totp(cur, username, password, totp_secret: str, is_admin=False):
    password_hash = ph.hash(password)
    cur.execute(
        """
        INSERT INTO users (username, password, is_admin, two_factor_secret, two_factor_enabled)
        VALUES (%s, %s, %s, %s, TRUE)
        RETURNING id
        """,
        (username, password_hash, bool(is_admin), totp_secret),
    )
    row = cur.fetchone()
    return row[0] if row else None


def create_user_hashed(cur, username, password_hash, is_admin=False):
    """Insert a user when the password is already hashed.
    Returns the new user's id or None on failure.
    """
    cur.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (%s, %s, %s) RETURNING id",
        (username, password_hash, bool(is_admin)),
    )
    row = cur.fetchone()
    if row:
        return row[0]
    try:
        return cur.lastrowid
    except Exception:
        return None


def verify_password(stored_hash, password):
    try:
        return ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHash):
        print("Password verification failed.")
        return False