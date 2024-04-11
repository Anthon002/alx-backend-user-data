#!/usr/bin/env python3
"""module for log filtering
"""
import re
import os
import mysql.connector
import logging
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")
_layouts = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str):
    """module for filtering log lines
    """
    extract, replace = (_layouts["extract"], _layouts["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """ module for creating new user data loggers .
    """
    data_logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    data_logger.setLevel(logging.INFO)
    data_logger.propagate = False
    data_logger.addHandler(stream_handler)
    return data_logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """module for creating a database connection
    """
    host_ = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    name_ = os.getenv("PERSONAL_DATA_DB_NAME", "")
    user_ = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    pwd_ = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    db_connection = mysql.connector.connect(
        host=host_,
        port=3306,
        user=user_,
        password=pwd_,
        database=name_,
    )
    return db_connection


def main():
    """Logs the information about user records in a table.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formats a LogRecord.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


if __name__ == "__main__":
    main()
