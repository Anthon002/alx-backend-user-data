#!/usr/bin/env python3
""" module for log fitering
"""
import re
import os
import mysql.connector
from typing import List
import logging


PII_FIELDS = ("name", "email", "phone", "ssn", "password")
patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
def filter_datum(fields: List[str], redaction: str, message: str, separator: str):
    """method to filter log lines.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    re_sub = re.sub(extract(fields, separator), replace(redaction), message)
    return re_sub
