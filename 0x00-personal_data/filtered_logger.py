#!/usr/bin/env python3
"""
A function called `filter_datum` that returns the log message obfuscated.
"""
import re


def filter_datum(fields, redaction, message, separator) -> str:
    """
    Filter Datum
    """
    pattern = '|'.join(f"{re.escape(field)}=.*?(?={re.escape(separator)}|$)"
                       for field in fields)
    return re.sub(pattern,
                  lambda m: m.group(0).split('=')[0] + '=' + redaction,
                  message)
