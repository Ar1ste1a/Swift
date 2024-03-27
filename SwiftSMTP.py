"""
SwiftSMTP is a command line interface for connecting to smtp servers and sending mail
items en masse to individuals in a list. This script was built to utilize mailing on a
system allowing open relay to send emails to other users on the system or out of band

Ar1ste1a <ar1ste1a@proton.me>
"""

import base64
import ipaddress
import json
import os.path
import ssl
import sys
import argparse
import re
import time
import uuid
from datetime import datetime, timezone
from socket import socket, AF_INET, SOCK_STREAM

# Variables
target_map = {}
targetURI = ''
BUFFER = 1024
FORCE = False
useTLS = False
useID = False
blue = "\033[1;32;40m"
green = "\033[1;34;40m"
yellow = "\033[1;33;40m"
red = "\033[1;31;40m"
reset = "\033[00m"
informational = "\033[2;37;40m"
HOSTNAME = ""
BANNER = """
░█▀▀▀█ ░█──░█ ▀█▀ ░█▀▀▀ ▀▀█▀▀ 　 ░█▀▀▀█ ░█▀▄▀█ ▀▀█▀▀ ░█▀▀█
─▀▀▀▄▄ ░█░█░█ ░█─ ░█▀▀▀ ─░█── 　 ─▀▀▀▄▄ ░█░█░█ ─░█── ░█▄▄█
░█▄▄▄█ ░█▄▀▄█ ▄█▄ ░█─── ─░█── 　 ░█▄▄▄█ ░█──░█ ─░█── ░█───
"""
sampleMessage = """
<!DOCTYPE html>
<html>
    <head>
    </head>
    <body>
        <p><h1>Hello From Swift SMTP!</h1></p>
    </body>
    <footer>
        <p>An Ar1ste1a Product</p>
        <p><a href="mailto:ar1ste1a@proton.me">ar1ste1a@proton.me</a></p>
    </footer> 
</html>
"""
msg_headers = [
    "MIME-Version: 1.0 ",
    "Date: .Date ",
    "Content-Language: en-US ",
    "Subject: .Subject ",
    "From: .From ",
    "To: .To ",
    "Reply-To: .ReplyTo ",
    "Content-Type: text/html; charset=UTF-8; format=flowed ",
    "Content-Transfer-Encoding: 7bit "
]
msg_content = [
    "\r\n.Message",
    "\r\n.\r\n"
]

def printTargetMap():
    global target_map
    if len(target_map.keys()) > 0:
        with open(f"target_map_{datetime.now().strftime('%a:%b:%d:%H:%M:%S')}", 'w') as w:
            w.write(json.dumps(target_map, indent=4))


def getSessionid():
    return str(uuid.uuid4())

def isEmail(email):
    regex = r"([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})"
    result = re.search(regex, email)
    if result:
        return True
    else:
        return False


def parseEmail(line):
    email = line.split("<")[1][:-1]
    return email


def getFirst(email):
    if email_aliased(email):
        #  Expected Format: First Last <email.html>
        name = email[:email.rfind("<")]
        if " " in name:
            return name.split(" ")[0].strip().capitalize()
        elif "." in name:
            return name.split(".")[0].strip().capitalize()
        else:
            return name.strip().capitalize()
    else:
        #  Expected Format: first[.]last@domain.com
        name = email[:email.rfind("@")]
        if "." in name:
            return name.split(".")[0].strip().capitalize()


def email_aliased(email):
    regex = r"^[\w\s]*\<([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})\>$"
    matches = re.findall(regex, email)
    if matches:
        return True
    else:
        return False


def get_email_from_alias(email):
    regex = r"([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})"
    result = re.search(regex,email)
    return result[0]


def getb64(data):
    return f"{base64.b64encode(data.encode('utf-8')).decode()}\r\n"


def getDate():
    from datetime import datetime
    offset = datetime.now().astimezone().strftime("%z")[:3]
    now = datetime.now().strftime("%a, %d %b %Y %H:%M:%S ") + offset + "00"
    return now


def leave(msg, socketConn, isErr=True):
    import sys
    _msg = ""
    print(blue + "Client: QUIT \r\n")
    if isErr:
        _msg = red + msg + reset
    else:
        _msg = yellow + msg + reset
    socketConn.send("QUIT \r\n".encode())
    socketConn.close()
    sys.exit(print(_msg))


def resolve_hostname(hostname):
    import sys
    from socket import gethostbyname
    try:
        ipaddr = gethostbyname(hostname)
        return ipaddr
    except Exception as e:
        sys.exit(print(red + f"Could not resolve hostname: \"{hostname}\"\n\tError: {e}"))


def get_hostname(host):
    from socket import gethostbyaddr

    if len(HOSTNAME) > 0:
        return HOSTNAME
    try:
        hostname = gethostbyaddr(host)
        return hostname
    except Exception as e:
        sys.exit(print(red + f"Could not get hostname for host: \"{host}\"\n\tError: {e}"))


def craft_message(reply_to, subject, mail_from, message, mail_to):
    mailFrom = mail_from
    msg_formatted_tmp = ''
    if not isEmail(reply_to):
        msg_headers.remove('Reply-To: .ReplyTo ')
    msg_no_format = "\r\n".join(msg_headers) + "".join(msg_content)
    msg_formatted = msg_no_format\
        .replace(".Subject", subject)\
        .replace(".From", mailFrom)\
        .replace(".Message", message)\
        .replace(".ReplyTo", reply_to)

    # replace with url if necessary
    msg_formatted_tmp = msg_formatted
    if len(targetURI) > 0:
        if useID:
            global target_map
            sess = getSessionid()
            target_map['test'] = {}
            target_map['test']['uuid'] = sess
            uri = f"{targetURI}/?sessionid={sess}"
            msg_formatted_tmp = msg_formatted_tmp.replace("${{.URL}}", uri)
            msg_formatted_tmp = msg_formatted_tmp.replace("${{.URL.PRETTY}}", targetURI)
        else:
            msg_formatted_tmp = msg_formatted_tmp.replace("${{.URL}}", targetURI)
        msg_formatted_tmp = msg_formatted_tmp.replace("${{.First}}", getFirst(mail_to))
    # Print Message Content
    print()
    print(informational + " Message Sample ".center(80, "*"))
    print(f"\n{msg_formatted_tmp.replace('.To', mail_to).replace('.Date', getDate())}\n")
    print(informational + "".center(80, "*"))
    return msg_formatted


def start_connection(mailserver, port, verbose):

    # Initialize IPv4 socket over TCP
    clientSock = socket(AF_INET, SOCK_STREAM)

    # Initial Connection
    try:
        clientSock.connect((mailserver, port))
        recv = clientSock.recv(BUFFER).decode()
        if recv[:3] != '220':
            leave("220: Reply not received on initial connection.", clientSock)
        if verbose:
            print(yellow + " Connected\n")
            print(green + f"Server: {recv}")
        clientSock.send("NOOP \r\n".encode())
        recv = clientSock.recv(BUFFER).decode()
        if recv[:3] != "250":
            leave(red + f"\n\n Error Connecting to server: {recv}", clientSock)
    except TimeoutError:
        leave(f"Timeout Connecting to {mailserver}:{str(port)}", clientSock)
    except Exception as e:
        leave(f"Unexpected error connecting to {mailserver}:{str(port)}\n\tError: {e}", clientSock)

    return clientSock


def send_helo(sock, verbose, domain):
    helo = f"EHLO {domain}\r\n"
    if verbose:
        print(blue + f"Client: {helo}" + reset)
    sock.send(helo.encode())
    recv = sock.recv(BUFFER).decode()
    if recv[:3] != '250':
        leave("250: \"HELO\" Reply not received from server.", sock)
    if verbose:
        to_print = recv.replace('\n', '\n\t\t')
        print(green + f"Server: {to_print}" + reset)

    return


def start_tls(sock, verbose, mailserver, port):
    try:
        sock.send("STARTTLS \r\n".encode())
        recv = sock.recv(BUFFER).decode()
        if recv.split()[0] != "250":
            leave(red + f"\n\n Error initializing \"STARTTLS\": {recv}", sock)
        if verbose:
            print(yellow + "\n\nInitiating TLS Connection... " + reset, end="")
        context = ssl.create_default_context()
        clientSock = context.wrap_socket(sock, server_hostname=get_hostname(mailserver))
        return clientSock
    except ssl.SSLError as s:
        clientSock.close()
        print(red + f"Error Connecting to {mailserver}:{str(port)}: {s}\n" + reset)
        sys.exit(0)


def authenticate(sock, verbose, auth_user, auth_password):
    authUser = auth_user
    if email_aliased(auth_user):
        authUser = get_email_from_alias(auth_user)
    auth = "AUTH LOGIN\r\n"
    if verbose:
        print(blue + f"Client: {auth}" + reset)
    sock.send(auth.encode())

    # Receive 334 and username request
    recv = sock.recv(BUFFER).decode()
    if recv[:3] != "334":
        leave(f"Error initializing authentication\n\tError: {recv}", sock)
    if verbose:
        print(green + f"Server: {recv}" + reset)

    # Send b64 encoded username
    resp = getb64(authUser)
    if verbose:
        print(blue + f"Client: {resp}" + reset)

    # Respond with username
    sock.send(resp.encode())

    # Receive 334 and password request
    recv = sock.recv(BUFFER).decode()
    if recv[:3] != "334":
        leave(f"Error authenticating with username\n\tError: {recv}", sock)

    if verbose:
        print(green + f"Server: {recv}" + reset)

    # Respond with password
    resp = getb64(auth_password)
    if verbose:
        print(blue + f"Client: {resp}" + reset)
    sock.send(resp.encode())

    # AUTH Response
    recv = sock.recv(BUFFER).decode()

    if verbose:
        print(green + f"Server: {recv}" + reset)

    if recv[:3] != "235":
        time.sleep(.5)
        sys.exit("Failed to Authenticate. Terminating Session")
        clientSock.send("QUIT\r\n".encode())

    return

def send_mail(sock, mail_to, mail_from, message, verbose):
    counter = 1
    total = len(mail_to)
    mailFrom = ""
    global target_map

    for email in mail_to:
        # MAIL FROM
        if email_aliased(mail_from):
            mailFrom = f"MAIL FROM: <{get_email_from_alias(mail_from)}>\r\n"
        else:
            mailFrom = f"MAIL FROM: <{mail_from}> \r\n"
        if verbose:
            print(blue + f"Client: {mailFrom}" + reset)
        sock.send(mailFrom.encode())
        recv = sock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}" + reset)
        if "bad" in recv.lower():
            leave(f"250: \"MAIL FROM\" Bad response: {recv}", sock)

        # Counter
        print(yellow + f"\n\t\tEmail {str(counter)}/{str(total)}\n" + reset)

        msg = message
        # replace with url if necessary
        if len(targetURI) > 0:
            if useID:
                sess = getSessionid()
                target_map[email] = {}
                target_map[email]['uuid'] = sess
                uri = f"{targetURI}/?sessionid={sess}"
                msg = msg.replace("${{.URL}}", uri)
                msg = msg.replace("${{.URL.PRETTY}}", targetURI)
            else:
                msg = msg.replace("${{.URL}}", targetURI)
            msg = msg.replace("${{.First}}", getFirst(email))

        # Mail object
        msg_out = msg.replace(".Date", getDate()).replace(".To", email)

        # RCPT TO
        rcptTo = f"RCPT TO: <{email}> \r\n"
        if verbose:
            print(blue + f"Client: {rcptTo}" + reset)
        sock.send(rcptTo.encode())
        recv = sock.recv(BUFFER).decode()
        if recv[:3] != "250":
            leave(f"Error adding RCPT TO\n\tError: {recv}", sock)

        if verbose:
            print(green + f"Server: {recv}" + reset)

        # DATA
        dataTo = "DATA \r\n"
        if verbose:
            print(blue + f"Client: {dataTo}" + reset)
        sock.send(dataTo.encode())
        recv = sock.recv(BUFFER).decode()
        if recv[:3] != "354":
            leave(f"Error designating DATA\n\tError: {recv}", sock)

        if verbose:
            print(green + f"Server: {recv}" + reset)

        # Message Content
        if verbose:
            print(blue + f"Client: \n{msg_out}" + reset)
        sock.send(msg_out.encode())
        recv = sock.recv(BUFFER).decode()
        if verbose:
            print(green + f"Server: {recv}" + reset)

        if useID:
            target_map[email]["status"] = recv.strip()
            target_map[email]["sent"] = datetime.now(timezone.utc).astimezone().isoformat()

        # QUIT
        if recv[:3] == "250":
            print(yellow + f"Message {counter}: Successfully sent" + reset)
        else:
            print(red + f"Message {counter}: Failed to send" + reset)
        counter += 1

    return


def smtp_client(mail_from, mail_to, auth_required, auth_user, auth_password, mailserver, verbose,
                message=sampleMessage, port=25, subject="Hello From Swift", reply_to=""):

    # Create Message
    msg = craft_message(reply_to, subject, mail_from, message, mail_to[0])

    # If not force, display message before continuing
    if not FORCE:
        user = input("\nWould you like to continue? \n\t(Y/N): ")
        if user[0].lower() == "n":
            sys.exit(print("Stopping at users request"))

    if verbose:
        print(yellow + "\nStarting Session...\t" + reset, end="")

    # Establish connection with mail server, test with NOOP
    clientSock = start_connection(mailserver, port, verbose)

    # HELO
    domain = ""
    if email_aliased(mail_from):
        domain = get_email_from_alias(mail_from).split("@")[1]
    else:
        domain = mail_from.split("@")[1]
    send_helo(clientSock, verbose, domain)

    # TLS STARTTLS must be after HELO
    if useTLS:
        clientSock = start_tls(clientSock, verbose, mailserver, port)
        if verbose:
            print(yellow + "Success" + reset)

    # AUTH
    if auth_required:
        authenticate(clientSock, verbose, auth_user, auth_password)

    # Send mail items to mail_to users
    send_mail(clientSock, mail_to, mail_from, msg, verbose)

    # Gracefully exit, send QUIT
    if verbose:
        time.sleep(.5)
        print(yellow + "Sending Complete" + reset)
    printTargetMap()
    leave(f"Terminating Program", clientSock)


def parseArgs():
    global HOSTNAME
    args_out = {}
    allEmails = []

    # Verbosity
    args_out["verbose"] = args.verbose

    # Parse URL
    if args.url:
        url = args.url.strip()
        if len(url) == 0:
            sys.exit(print(red + "Please ensure url is correct and try again." + reset))
        global targetURI
        targetURI = url

    # Parse MAIL TO
    emails = []
    if args.mail_to:
        allEmails = args.mail_to.split(",")
    elif args.read_mail_to:
        path = args.read_mail_to
        if os.path.exists(path):
            allEmails = open(path, "r").read().split("\n")
    else:
        sys.exit(print(red + "A SEND TO email.html is required." + reset))

    for email in allEmails:
        if not isEmail(email):
            if not FORCE:
                user = input(yellow + f"{email} - is not a valid email.html, would you still like to add it?\n\t(Y/N): ")
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
            user = input(yellow + f"The MAIL FROM email.html provided appears to be incorrect. Would you like to continue? \n\t{emails_provided}\n\t(Y/N): ")
            if user[0].lower() == "n":
                sys.exit(print(red + "Please ensure email.html is correct and try again." + reset))
    args_out["mail_from"] = args.mail_from

    # Parse User Auth Requirement and Credentials
    if args.auth_user or args.auth_password:
        args_out["auth_required"] = True
        if not (args.auth_password and (args.auth_user or args.reuse_sender)):
            sys.exit(print(red + "Auth Error: Please provide a user and password" + reset))
        if args.reuse_sender:
            args_out["auth_user"] = args.mail_from
        elif args.auth_user:
            args_out["auth_user"] = args.auth_user
        args_out["auth_password"] = args.auth_password
    else:
        args_out["auth_required"] = False
        args_out["auth_user"] = None
        args_out["auth_password"] = None

    # Parse REPLY TO
    if args.reply_to:
        if not isEmail(args.reply_to):
            sys.exit(red + "Please supply a valid \"reply-to\" email.html address" + reset)
        else:
            args_out["reply_to"] = args.reply_to

    # Parse message
    if args.message:
        args_out["message"] = args.message
    elif args.read_message:
        if os.path.exists(args.read_message):
            args_out["message"] = open(args.read_message).read()
        else:
            sys.exit(print(red + f"The path does not exist.\n\t{args.read_message}" + reset))

    # Resolve Mailserver
    try:
        args_out["mailserver"] = str(ipaddress.IPv4Address(args.mailserver))
    except ValueError:
        args_out["mailserver"] = resolve_hostname(args.mailserver)
        HOSTNAME = args.mailserver

    # Set port
    if args.port:
        args_out["port"] = args.port

    # Set subject
    if args.subject_line:
        args_out["subject"] = args.subject_line

    # TLS
    if args.tls:
        global useTLS
        useTLS = True

    # Sessionid
    if args.sessionid:
        global useID
        useID = True
        if not 'message' in args_out.keys():
            sys.exit(print(red + f"A message is required to replace a variable.\n\t" + reset))
        if "${{.URL}}" not in args_out["message"]:
            sys.exit(print(red + f"The message does not include a url to set a session id with.\n\t{args_out['message']}" + reset))

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
parser.add_argument('-i', '--sessionid', default=False, action='store_true', help='create a sessionid for each target')
parser.add_argument('-u', '--url', type=str, required=False, help='URL to replace variable \'${{.URL}}\' with')
parser.add_argument('-v', '--verbose', default=False, action='store_true', help='increase verbosity')
parser.add_argument('-t', '--mail-to', type=str, required=False, help='comma delimited list of email.html address to send to')
parser.add_argument('-T', '--read-mail-to', type=str, required=False, help='new-line delimited list of email.html address to send to')
parser.add_argument('-f', '--mail-from', type=str, required=True, help='send from this address')
parser.add_argument('-m', '--message', type=str, required=False, help='message content')
parser.add_argument('-M', '--read-message', type=str, required=False, help='read message from file')
parser.add_argument('-s', '--subject-line', type=str, required=False, help='subject line')
parser.add_argument('-p', '--port', type=int, required=False, help='server port')
parser.add_argument('-S', '--mailserver', type=str, required=True,  help='mail server')
parser.add_argument('-U', '--auth-user', type=str, required=False,  help='user for authentication')
parser.add_argument('-P', '--auth-password', type=str, required=False, help='password for authentication')
parser.add_argument('-F', '--force', default=False, action='store_true', help='continue without prompting')
parser.add_argument('-r', '--reply-to', type=str, required=False, help='address specified for email.html replies')
parser.add_argument('-E', '--tls', default=False, action='store_true', help='utilize TLS for connection')
parser.add_argument('-x', '--reuse-sender', default=False, action='store_true',  help='use sender as authentication user. Requires -P')
args = parser.parse_args()

if __name__ == "__main__":
    main()
