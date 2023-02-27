import base64
import ipaddress
import os.path
import sys
import argparse
import re
import time
from socket import socket, AF_INET, SOCK_STREAM

# Variables
BUFFER = 1024
FORCE = False
blue = "\033[1;32;40m"
green = "\033[1;34;40m"
yellow = "\033[1;33;40m"
red = "\033[1;31;40m"
informational = "\033[2;37;40m"
BANNER = """
░█▀▀▀█ ░█──░█ ▀█▀ ░█▀▀▀ ▀▀█▀▀ 　 ░█▀▀▀█ ░█▀▄▀█ ▀▀█▀▀ ░█▀▀█
─▀▀▀▄▄ ░█░█░█ ░█─ ░█▀▀▀ ─░█── 　 ─▀▀▀▄▄ ░█░█░█ ─░█── ░█▄▄█
░█▄▄▄█ ░█▄▀▄█ ▄█▄ ░█─── ─░█── 　 ░█▄▄▄█ ░█──░█ ─░█── ░█───
"""


def isEmail(email):
    regex = r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$"
    result = re.search(regex, email)
    if result:
        return True
    else:
        return False


def getb64(data):
    return f"{base64.b64encode(data.encode('utf-8')).decode()}\r\n"


def getDate():
    from datetime import datetime
    offset = datetime.now().astimezone().strftime("%z")[:3]
    now = datetime.now().strftime("%a, %d %b %Y %H:%M:%S ") + offset + "00"
    return now


def leave(msg, socketConn):
    import sys
    print(blue + "Client: QUIT\r\n")
    socketConn.send("QUIT\r\n".encode())
    socketConn.close()
    sys.exit(print(red + msg))


def resolve_hostname(hostname):
    import sys
    from socket import gethostbyname
    try:
        ipaddr = gethostbyname(hostname)
        return ipaddr
    except Exception as e:
        sys.exit(print(red + f"Could not resolve hostname: \"{hostname}\"\n\tError: {e}"))


def smtp_client(mail_from, mail_to, auth_required, auth_user, auth_password, mailserver, verbose,
                message="Hello", port=25, subject="Test", reply_to=None):
    to = '; '.join(mail_to) if len(mail_to) > 1 else mail_to[0]

    if reply_to:
        msg_out = f"Date: {getDate()}" \
                  f"\r\nMIME-Version: 1.0" \
                  f"\r\nContent-Language: en-US" \
                  f"\r\nTo: {to}" \
                  f"\r\nFrom: {mail_from}" \
                  f"\r\nReply-To:{reply_to}" \
                  f"\r\nSubject:{subject}" \
                  f"\r\nContent-Type: text/html; charset=UTF-8; format=flowed" \
                  f"\r\nContent-Transfer-Encoding: 7bit" \
                  f"\r\n\r\n{message}" \
                  f"\r\n.\r\n"
    else:
        msg_out = f"Date: {getDate()}" \
                  f"\r\nMIME-Version: 1.0" \
                  f"\r\nContent-Language: en-US" \
                  f"\r\nTo: {to}" \
                  f"\r\nFrom: {mail_from}" \
                  f"\r\nSubject:{subject}" \
                  f"\r\nContent-Type: text/html; charset=UTF-8; format=flowed" \
                  f"\r\nContent-Transfer-Encoding: 7bit" \
                  f"\r\n\r\n{message}" \
                  f"\r\n.\r\n"

    print(informational + " Message Content ".center(80, "*"))
    print(f"\n{msg_out}\n")
    print(informational + "".center(80, "*"))

    if not FORCE:
        user = input("\nWould you like to continue? \n\t(Y/N): ")
        if user[0].lower() == "n":
            sys.exit(print("Stopping at users request"))

    if verbose:
        print()
        print(yellow + "Starting Session")
        print()

    clientSock = socket(AF_INET, SOCK_STREAM)

    # Initial Connection
    try:
        clientSock.connect((mailserver, port))
    except TimeoutError as t:
        leave(f"Timeout Connecting to {mailserver}:{str(port)}", clientSock)
    except Exception as e:
        leave(f"Unexpected error connecting to {mailserver}:{str(port)}", clientSock)
    recv = clientSock.recv(BUFFER).decode()
    if recv[:3] != '220':
        leave("220: Reply not received on initial connection.")

    # HELO
    helo = "EHLO swift\r\n"     # EHLO for ESMTP
    clientSock.send(helo.encode())
    recv = clientSock.recv(BUFFER).decode()
    if recv[:3] != '250':
        leave("250: \"HELO\" Reply not received from server.", clientSock)

    # AUTH
    if auth_required:
        auth = "AUTH LOGIN\r\n"
        if verbose:
            print(blue + f"Client: {auth}")
        clientSock.send(auth.encode())

        # Receive 334 and username request
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")

        # Send b64 encoded username
        resp = getb64(auth_user)
        if verbose:
            print(blue + f"Client: {resp}")

        # Respond with username
        clientSock.send(resp.encode())

        # Receive 334 and password request
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")

        # Respond with password
        resp = getb64(auth_password)
        if verbose:
            print(blue + f"Client: {resp}")
        clientSock.send(resp.encode())

        # AUTH Response
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")
        if "535" in recv:
            time.sleep(1)
            sys.exit("Failed to Authenticate. Terminating Session")
            clientSock.send("QUIT\r\n".encode())

    counter = 1
    total = len(mail_to)
    for email in mail_to:

        # MAIL FROM
        mailFrom = f"MAIL FROM: <{mail_from}>\r\n"
        if verbose:
            print(blue + f"Client: {mailFrom}")
        clientSock.send(mailFrom.encode())
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")
        if "bad" in recv.lower():
            leave(f"250: \"MAIL FROM\" Bad response: {recv}", clientSock)

        print(yellow + f"\nEmail {str(counter)}/{str(total)}\n")
        if reply_to:
            msg_out = f"Date: {getDate()}" \
                      f"\r\nMIME-Version: 1.0" \
                      f"\r\nContent-Language: en-US" \
                      f"\r\nTo: {email}" \
                      f"\r\nFrom: {mail_from}" \
                      f"\r\nReply-To: {reply_to}" \
                      f"\r\nSubject:{subject}" \
                      f"\r\nContent-Type: text/html; charset=UTF-8; format=flowed" \
                      f"\r\nContent-Transfer-Encoding: 7bit" \
                      f"\r\n\r\n{message}" \
                      f"\r\n.\r\n"
        else:
            msg_out = f"Date: {getDate()}" \
                      f"\r\nMIME-Version: 1.0" \
                      f"\r\nContent-Language: en-US" \
                      f"\r\nTo: {email}" \
                      f"\r\nFrom: {mail_from}" \
                      f"\r\nSubject:{subject}" \
                      f"\r\nContent-Type: text/html; charset=UTF-8; format=flowed" \
                      f"\r\nContent-Transfer-Encoding: 7bit" \
                      f"\r\n\r\n{message}" \
                      f"\r\n.\r\n"

        # RCPT TO
        rcptTo = f"RCPT TO: <{email}>\r\n"
        if verbose:
            print(blue + f"Client: {rcptTo}")
        clientSock.send(rcptTo.encode())
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")

        # DATA
        dataTo = "DATA\r\n"
        if verbose:
            print(blue + f"Client: {dataTo}")
        clientSock.send(dataTo.encode())
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")

        # Message Content
        if verbose:
            print(blue + f"Client: \n{msg_out}")
        clientSock.send(msg_out.encode())
        recv = clientSock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}")

        # QUIT
        if recv[:3] == "250":
            print(yellow + f"Message {counter}: Successfully sent")
            # leave(f"Message Successfully sent: {recv}", clientSock)
        else:
            print(red + f"Message {counter}: Failed to send")
        counter += 1

    leave(f"Sending Complete", clientSock)


def parseArgs():
    args_out = {}

    # Verbosity
    args_out["verbose"] = args.verbose

    # Parse User Auth Requirement and Credentials
    if args.auth_user or args.auth_password:
        args_out["auth_required"] = True
        if not (args.auth_password and args.auth_user):
            sys.exit(print("Please provide but a user and password"))
        args_out["auth_user"] = args.auth_user
        args_out["auth_password"] = args.auth_password
    else:
        args_out["auth_required"] = False
        args_out["auth_user"] = None
        args_out["auth_password"] = None

    # Parse MAIL TO
    emails = []
    if args.mail_to:
        allEmails = args.mail_to.split(",")
    elif args.read_mail_to:
        path = args.read_mail_to
        if os.path.exists(path):
            allEmails = open(path, "r").read().split()
    else:
        sys.exit(print(red + "A SEND TO email is required."))
    for email in allEmails:
        if not isEmail(email):
            if not FORCE:
                user = input(yellow + f"{email} - is not a valid email, would you still like to add it?\n\t(Y/N): ")
                if user[0].lower() == "y":
                    emails.append(email)
            else:
                emails.append(email)
        else:
            emails.append(email)
    args_out["mail_to"] = emails

    # Parse MAIL FROM
    if not isEmail(args.mail_from):
        if not FORCE:
            emails_provided = f"{args.mail_from}"
            user = input(yellow + f"The MAIL FROM email provided appears to be incorrect. Would you like to continue? \n\t{emails_provided}\n\t(Y/N): ")
            if user[0].lower() == "n":
                sys.exit(print(red + "Please ensure email is correct and try again."))
    args_out["mail_from"] = args.mail_from

    # Parse REPLY TO
    if args.reply_to:
        if not isEmail(args.reply_to):
            sys.exit(red + "Please supply a valid \"reply-to\" email address")
        else:
            args_out["reply_to"] = args.reply_to


    # Parse message
    if args.message:
        args_out["message"] = args.message
    elif args.read_message:
        if os.path.exists(args.read_message):
            args_out["message"] = open(args.read_message).read()
        else:
            sys.exit(print(red + f"The path does not exist.\n\t{args.read_message}"))

    # Resolve Mailserver
    try:
        args_out["mailserver"] = str(ipaddress.IPv4Address(args.mailserver))
    except ValueError:
        args_out["mailserver"] = resolve_hostname(args.mailserver)

    # Set port
    if args.port:
        args_out["port"] = args.port

    # Set subject
    if args.subject_line:
        args_out["subject"] = args.subject_line

    return args_out


def main():
    global FORCE

    bannerPrint = yellow + BANNER
    print("\n\n")
    print(bannerPrint)
    FORCE = args.force
    mailArgs = parseArgs()
    smtp_client(**mailArgs)


# Argparse
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', default=False, action='store_true', help='increase verbosity')
parser.add_argument('-t', '--mail-to', type=str, required=False, help='comma delimited list of email address to send to')
parser.add_argument('-T', '--read-mail-to', type=str, required=False, help='new-line delimited list of email address to send to')
parser.add_argument('-f', '--mail-from', type=str, required=True, help='send from this address')
parser.add_argument('-m', '--message', type=str, required=False, help='message content')
parser.add_argument('-M', '--read-message', type=str, required=False, help='read message from file')
parser.add_argument('-s', '--subject-line', type=str, required=False, help='subject line')
parser.add_argument('-p', '--port', type=int, required=False, help='server port')
parser.add_argument('-S', '--mailserver', type=str, required=True,  help='mail server')
parser.add_argument('-U', '--auth-user', type=str, required=False,  help='user for authentication')
parser.add_argument('-P', '--auth-password', type=str, required=False, help='password for authentication')
parser.add_argument('-F', '--force', default=False, action='store_true', help='continue without prompting')
parser.add_argument('-r', '--reply-to', type=str, required=False, help='address specified for email replies')
args = parser.parse_args()

if __name__ == "__main__":
    main()
