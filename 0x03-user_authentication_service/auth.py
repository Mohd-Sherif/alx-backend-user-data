#!/usr/bin/env python3
"""
Auth File
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Hash Password with Salt
    """
    return bcrypt.hashpw(password.encode("UTF-8"), bcrypt.gensalt())
