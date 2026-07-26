"""Shared rate limiter instance.

Lives in its own module (not main.py) so route modules can import it
without creating a circular import with app.main.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
