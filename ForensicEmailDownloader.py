"""
Licensed under MIT License, (c) B. Fischer
"""
import argparse
import datetime
import email
import imapclient
from imapclient import  imap_utf7
import logging
import os
import platform
import pickle
import ssl
import subprocess
import sys
import time
import urllib.request


def get_linux_version():
    output = subprocess.check_output(['lsb_release', '-a']).decode('utf-8')
    version = None
    for line in output.split('\n'):
        if 'Release' in line:
            version = line.split(':')[1].strip()
            break
    return version

def get_macos_version():
    return platform.mac_ver()[0]

def get_windows_version():
    return platform.win32_ver()[1]
def delete_last_lines(n=1):
    # Delete n lines
    for _ in range(n):
        # Move the cursor to the beginning of the line
        sys.stdout.write('\033[F')
        # Delete the line with spaces
        sys.stdout.write('\033[K')
def test_imap_credentials(imapurl, sslport, username, password):
    ssl_context = ssl.create_default_context()

    # don't check if certificate hostname doesn't match target hostname
    ssl_context.check_hostname = False

    # don't check if the certificate is trusted by a certificate authority
    ssl_context.verify_mode = ssl.CERT_NONE
    imap_server = imapclient.IMAPClient(host=imapurl, port=sslport, ssl_context=ssl_context)
    try:
        # Execute authentication
        imap_server.login(username, password)
        imapTestResult = 1
        imapTestTimestamp = time.time()
        return imapTestResult, imapTestTimestamp
    except Exception as e:
        imapTestResult = 0
        imapTestTimestamp = time.time()
        return imapTestResult, imapTestTimestamp

    finally:
        # Verbindung zum IMAP-Server schließen
        imap_server.logout()

#########################
# global variables
#########################
programTitle = """
 ______ ______ _____         ______                       _      ______                 _ _ _____                      _                 _           
|  ____|  ____|  __ \       |  ____|                     (_)    |  ____|               (_) |  __ \                    | |               | |          
| |__  | |__  | |  | |______| |__ ___  _ __ ___ _ __  ___ _  ___| |__   _ __ ___   __ _ _| | |  | | _____      ___ __ | | ___   __ _  __| | ___ _ __ 
|  __| |  __| | |  | |______|  __/ _ \| '__/ _ \ '_ \/ __| |/ __|  __| | '_ ` _ \ / _` | | | |  | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |    | |____| |__| |      | | | (_) | | |  __/ | | \__ \ | (__| |____| | | | | | (_| | | | |__| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |   
|_|    |______|_____/       |_|  \___/|_|  \___|_| |_|___/_|\___|______|_| |_| |_|\__,_|_|_|_____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|    Version 0.1 

(C) 2023 - BrunoFischerBerlin - MIT Licence
Github: https://github.com/BrunoFischerGermany/FED-ForensicEmailDownloader
Email: info @ bruno-fischer.de
"""

example1 = "python3 ForensicEmailDownloader.py --username user@example.com --password mypassword --imapurl imap.example.com --output C:\\tmp"
example2 = "python3 ForensicEmailDownloader.py -u user@example.com -p mypassword -i imap.example.com -o /tmp/mails"

#############################
# Main Window
#############################
def main(output=None, username=None, password=None, imapurl=None, sslport=None, evidence=None, examiner=None, case=None):

    imapTestTimestamp = None
    imapTestResult = 0
    try:
        urllib.request.urlopen('https://www.google.com', timeout=5)
        print("√ Internet connection exists.\n")
    except:
        print("Internet connection does not exists. Please check the Internet connection. This program will now be closed.")
        try:
            input("Press enter to exit this program.")
        except SyntaxError:
            pass
        exit()
    # Check an credential.file (credential.pkl) exists in the same folder of this program
    pickle_file = "credential.pkl"
    if os.path.exists(pickle_file) and os.access(pickle_file, os.W_OK):
        print('√ Credential File found.\n')
        with open(pickle_file, 'rb') as f:
            var_list = pickle.load(f)
        username, password, imapurl, sslport, output, examiner, case, evidence = var_list
   # Check Args found. Show and Show them.

    # check Connection to IMAP Server. If False, then check IMAPUrl, SSLPort, username and password
    if args.username:
        username = args.username
    if not username:
        username = ""
    if args.password:
        password = args.password
    if not password:
        password = ""
    if args.imapurl:
        imapurl = args.imapurl
    if not imapurl:
        imapurl = ""
    if args.sslport:
        sslport = args.sslport
    if not sslport:
        sslport = 993
    if args.output:
        output = args.output
    if not output:
        output = "./"
    if args.examiner:
        examiner = args.examiner
    if not examiner:
        examiner = ""
    if args.case:
        case = args.case
    if not case:
        case = ""
    if args.evidence:
        evidence = args.evidence
    if not evidence:
        evidence = ""

    # Get System Data

    login_name = os.getlogin()
    system = platform.system()

    if system == "Windows":
        osSystem = "Windows"
        osVersion = get_windows_version()
    elif system == "Darwin":
        osSystem = "MacOS"
        osVersion = get_macos_version()
    elif system == "Linux":
        osSystem = "Linux"
        osVersion = get_linux_version()
    else:
        osSystem = "Other"
        osVersion = "Other"

    ## Print out System data
    print(f'operating system: {osSystem}')
    print(f'operating system version: {osVersion}')
    print(f'computer user: {login_name}\n')

    ########################################
    # Print out the defaults
    ########################################
    while True:
        if imapTestTimestamp is not None:
            imapTestString = "Result: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(imapTestTimestamp))
            if imapTestResult == 0:
                imapTestString += " failed "
            if imapTestResult == 1:
                imapTestString += " successful "
        else:
            imapTestString = "Result: Credential not tested yet"

        print(f'[1] Username/Email-Address:\t\t{username}')
        print(f'[2] Password:\t\t\t\t{password}')
        print(f'[3] IMAP-Server:\t\t\t{imapurl}')
        print(f'[4] IMAP-Server-SSL-Port:\t\t{sslport}')
        print(f'[5] Output-Path :\t\t\t{output}')
        print(f'[6] Examiner:\t\t\t\t{examiner}')
        print(f'[7] Case:\t\t\t\t{case}')
        print(f'[8] Evicence:\t\t\t\t{evidence}')
        print(f'[T] test imap credentials\t\t{imapTestString}')
        print(f'[S] save email data to output path')
        # 16 Lines

        choose = input('Please select an option [1-8; S; T] (q to exit): ')
        # End loop when 'q' is entered
        if choose == 'q':
            break
        if choose.upper()== '1':
            username = input("Please enter the username/email address: ")
        if choose.upper() == '2':
            password = input("Please enter the password: ")
        if choose.upper() == '3':
            imapurl = input("Please enter the URL to the IMAP server: ")
        if choose.upper() == '4':
            sslport = input("Please specify the port to the IMAP server: ")
        if choose.upper() == '5':
            output = input("Please enter the output path: ")
        if choose.upper() == '6':
            examiner = input("Please specify an Examiner: ")
        if choose.upper() == '7':
            case = input("Please specify the case number: ")
        if choose.upper() == '8':
            evidence = input("Please specify the evidence object number: ")
        if choose.upper() == "T":
            # Test the Credentials
            imapTestResult, imapTestTimestamp = test_imap_credentials(imapurl, sslport, username, password)
        if choose.upper() != 'T' and choose.upper() != 'S':
            with open(pickle_file, 'wb') as f:
                pickle.dump([username, password, imapurl, sslport, output, examiner, case, evidence], f)
            print('Credentical File updated')
        else:
            ## emty line for not shown credential file updated
            print()
        delete_last_lines(12)



if __name__ == '__main__':
    os.system('mode con: cols=170 lines=40')
    parser = argparse.ArgumentParser(description={programTitle},
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="""Example:
{example1}
{example2}

""")
    print(f"""
{programTitle}

Example: 
{example1}
{example2}
""")
    parser.add_argument('-i', '--imapurl', dest='imapurl', help='IMAP-URL', default=None)
    parser.add_argument('-u', '--username', dest='username', help='Benutzername', default=None)
    parser.add_argument('-p', '--password', dest='password', help='Passwort', default=None)
    parser.add_argument('-o', '--output', dest='output', help='Sicherungspfad', default=None)
    parser.add_argument('-s', '--sslport', dest='sslport', help='SSL-Port', default=None)
    parser.add_argument('-x', '--examiner', dest='examiner', help='Examiner', default=None)
    parser.add_argument('-c', '--case', dest='case', help='Fallnummer', default=None)
    parser.add_argument('-e', '--evidence', dest='evidence', help='Asservatsnummer', default=None)
    args = parser.parse_args()

    main(**vars(args))