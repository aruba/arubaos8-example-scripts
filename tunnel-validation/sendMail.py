#!/usr/bin/env python3
# ------------------------------------------------------------------------------
#
# Author: pmalviya@arubanetworks.com, Aruba Engineering Group
# Organization: Aruba, a Hewlett Packard Enterprise company
#
# Version: 2017.03
#
#
# Copyright (c) Hewlett Packard Enterprise Development LP
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#
# ------------------------------------------------------------------------------

import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from os.path import basename
from email.mime.base import MIMEBase
from email import encoders

localtime = time.asctime(time.localtime(time.time()))
SUBJECT = "Tunnel Validation script - " + localtime


def send_email(to_address, from_address, passwd, smtp_server, port, error_log, fd):
    """
    This function is to send an email to user specifying the error logs for controller

    :param to_address: email address of an user
    :param error_log: error messages for commands
    :param ip: ip address of an controller
    :param cmd: command name to be written in log file
    :returns attr: attribute list for a command

    """
    recipients = to_address
    message = MIMEMultipart()
    message['From'] = from_address
    message['To'] = ", ".join(recipients)
    message['Subject'] = SUBJECT
    body = error_log

    message.attach(MIMEText(body, 'plain'))

    for f in fd or []:
        with open(f, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=basename(f)
            )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
        message.attach(part)

    try:
        server = smtplib.SMTP(smtp_server, port)
        server.starttls()
        server.login(from_address, passwd)
        text = message.as_string()
        server.send_message(message)
        server.quit()
        print('email sent')
    except Exception as e:
        print('email could not be sent {}'.format(e))
        pass
