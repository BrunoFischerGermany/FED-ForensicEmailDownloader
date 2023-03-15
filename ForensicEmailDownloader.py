"""
Licensed under MIT License, (c) B. Fischer
"""
import argparse
import datetime
import dns.resolver
import email
import hashlib
import imapclient
from imapclient import imap_utf7
import logging
import os
import platform
import pickle
import re
import requests
import ssl
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

def formatDuration(duration):
    if duration >= 3600:
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        seconds = int(duration % 60)
        duration_str = f"{hours:02}:{minutes:02}:{seconds:02}"
    elif duration >= 60:
        minutes = int(duration // 60)
        seconds = int(duration % 60)
        duration_str = f"{minutes:02}:{seconds:02}"
    else:
        duration_str = f"{duration:.2f}s"

    return duration_str
def get_imap_settings(domain):

    # Retrieve the web page for the given domain
    url = f"https://autoconfig.thunderbird.net/v1.1/{domain}"
    response = requests.get(url)
    imapurl = "-empty-value-"
    sslport = 993

    if response.status_code != 200:
        return imapurl, sslport
    else:
    # Extrahieren der URL für die XML-Konfigurationsdatei
        root = ET.fromstring(response.content)
        for incoming_server in root.findall("./emailProvider/incomingServer[@type='imap']"):
            if incoming_server.find("socketType").text == "SSL":
                imapurl = incoming_server.find("hostname").text
                sslport = incoming_server.find("port").text
                return imapurl, sslport
    return imapurl, sslport
def validate_email(email):
    # Check the format of the email address with a regular expression
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        return False

    # Check if the domain exists by performing a DNS query
    domain = email.split("@")[1]
    try:
        dns.resolver.resolve(domain, 'MX')
    except dns.resolver.NXDOMAIN:
        return False

    # Extract the domain from the email address
    return domain


def convert_size(size_bytes):
    # Definiere die Namen der Maßeinheiten und ihre Größen in Bytes
    units = ["B", "KB", "MB", "GB", "TB"]
    sizes = [1024 ** i for i in range(len(units))]

    # Finde die passende Maßeinheit
    for i, size in enumerate(sizes[::-1]):
        if size_bytes >= size:
            return f"{round(size_bytes / size, 2)} {units[len(units) - i - 1]}"

    # Wenn die Größe kleiner als 1 Byte ist
    return f"{size_bytes} B"

def calculate_file_md5(filename):
    with open(filename, 'rb') as f:
        md5_hash = hashlib.md5()
        while chunk := f.read(8192):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

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

def export_email(username, password, imapurl, sslport, output, examiner, case, evidence, osSystem, osVersion, login_name):
    global lines
    starttime = time.time()
    ssl_context = ssl.create_default_context()

    # don't check if certificate hostname doesn't match target hostname
    ssl_context.check_hostname = False

    # don't check if the certificate is trusted by a certificate authority
    ssl_context.verify_mode = ssl.CERT_NONE
    now = datetime.datetime.now()
    folder_path = os.path.join(output, now.strftime("%Y-%m-%d_%H-%M-%S"))
    # Folder create
    os.makedirs(folder_path)
    if os.path.exists(folder_path) and os.access(folder_path, os.W_OK):
        print(f'The backup path "{folder_path}" exists and is writeable.')
        lines += 1
        output = folder_path
    else:
        print(f'The backup path "{folder_path}" could not be created.')
        lines += 1
        exit()
    logging_file = output + '/' + now.strftime("%Y-%m-%d_%H-%M-%S") + '.txt'
    if os.path.exists(logging_file):
        print(f'The log file already {logging_file} exists and will be overwritten.')
    else:
        print(f'The log file  {logging_file} will created.')
    lines += 1
    startText = f"""{programTitle}
case number: {case}
evidence number: {evidence}
examiner: {examiner}

IMAP Credentials
Username / Email-address: »{username}«
Password: »{password}«
IMAP-Server: »{imapurl}«
IMAP-SSL-Port: »{sslport}«

operating system: {osSystem}
operating system version: {osVersion}
computer user: {login_name}

"""
    with open(logging_file, 'w', encoding='utf-8') as f:
        f.write(startText)
    logging.basicConfig(filename=logging_file, level=logging.INFO, encoding='utf-8',
                        format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info('Internet connection exists.')
    logging.info(f'The backup path "{folder_path}" exists and is writeable.')

    email_folder_path = os.path.join(output, username)
    os.makedirs(email_folder_path, exist_ok=True)
    logging.info(f'The email-Folder "{email_folder_path}" was created.')

    imap_server = imapclient.IMAPClient(host=imapurl, port=sslport, ssl_context=ssl_context)
    try:
        # Execute authentication
        imap_server.login(username, password)
        imap_server.select_folder('INBOX', readonly=True)

        folder_list = imap_server.list_folders()
        for folder in folder_list:
            decoded_folder = imap_utf7.decode(folder[2])
            # Create the folder structure in the destination directory
            imap_sub_folder = os.path.join(email_folder_path, decoded_folder)
            os.makedirs(imap_sub_folder, exist_ok=True)
            logging.info(f"Folder {imap_sub_folder} created.")
    except Exception as e:
        logging.error(f"Error when using imapclient: {e}")
        # print(f"Error when using imapclient: {e} ")

    finally:
        # Close connection to IMAP server
        imap_server.logout()
    with open(logging_file, 'a', encoding='utf-8') as f:
        f.write("\nOutput of the created folder structure\n")

    print_directory_tree(email_folder_path, logging_file, output)
    with open(logging_file, 'a', encoding='utf-8') as f:
        f.write("\nReading the number and size of emails in the folders\n")
    total_email = 0
    total_size = 0
    imap_server = imapclient.IMAPClient(host=imapurl, port=sslport, ssl_context=ssl_context)
    try:
        imap_server.login(username, password)
        folder_list = imap_server.list_folders()
        for folder in folder_list:
            try:
                decoded_folder = imap_utf7.decode(folder[2])
                select_result = imap_server.select_folder(decoded_folder, readonly=True)
                print(f'Processing folder {decoded_folder}')
                if select_result is None:
                    logging.error(f"Could not select folder {decoded_folder}")
                    continue
                else:
                    email_ids = imap_server.search('ALL', None)
                    if not email_ids:
                        logging.info(f'no emails found in the folder »{decoded_folder}«')
                    else:
                        folder_total_size = 0
                        email_count = len(email_ids)
                        total_email += email_count
                        email_count_format = '{:,.0f}'.format(email_count)
                        for email_id in email_ids:
                            email_data = imap_server.fetch(email_id, ['RFC822.SIZE'])
                            email_size = email_data[email_id][b'RFC822.SIZE']
                            folder_total_size += email_size
                            total_size += email_size
                            continue
                        logging.info(f'{email_count_format} emails [Size: {convert_size(folder_total_size)}] found in the folder »{decoded_folder}«.')
                time.sleep(0.8)
                delete_last_lines(1)
            except Exception as e:
                logging.error(f"Error when processing folder {decoded_folder}: {e}")
    except Exception as e:
        logging.error(f"Error when using imapclient: {e}")
    finally:
        total_email_format = '{:,.0f}'.format(total_email)
        logging.info(f"{total_email_format} emails [Size: {convert_size(total_size)}] found in the mailbox")
        print(f"{total_email_format} emails [Size: {convert_size(total_size)}] found in the mailbox")
        lines += 1
        imap_server.logout()
    with open(logging_file, 'a', encoding='utf-8') as f:
        f.write("\nDownload all Emails to eml\n")
    total_email_download = 0
    total_size_download = 0
    imap_server = imapclient.IMAPClient(host=imapurl, port=sslport, ssl_context=ssl_context)
    try:
        imap_server.login(username, password)
        folder_list = imap_server.list_folders()
        for folder in folder_list:
            try:
                decoded_folder = imap_utf7.decode(folder[2])
                select_result = imap_server.select_folder(decoded_folder, readonly=True)
                print(f'Processing folder {decoded_folder}')
                if select_result is None:
                    logging.error(f"Could not select folder {decoded_folder}")
                    continue
                else:
                    email_ids = imap_server.search('ALL', None)
                    if not email_ids:
                        logging.info(f'no emails found in the folder »{decoded_folder}«')
                    else:
                        folder_total_size = 0
                        email_count = len(email_ids)
                        total_email_download += email_count
                        email_count_format = '{:,.0f}'.format(email_count)
                        imap_sub_folder = os.path.join(email_folder_path, decoded_folder)
                        for email_id in email_ids:
                            raw_email = imap_server.fetch([email_id], ['RFC822'])[email_id][b'RFC822']

                            # Parse raw email data
                            email_message = email.message_from_bytes(raw_email)
                            #uid = imap_server.fetch([email_id], ['UID'])[email_id][b'UID']

                            # Create a filename for the EML file
                            email_id_nr = str(email_id)
                            email_filename = f"{imap_sub_folder}\Message_{email_id_nr.zfill(6)}.eml"
                            # Write the email message to a file
                            with open(email_filename, 'w', encoding="utf-8") as f:
                                f.write(raw_email.decode('utf-8'))
                            file_md5 = calculate_file_md5(email_filename)
                            # Print the file size in a human-readable format
                            file_size = os.path.getsize(email_filename)
                            logging.info(f"Downloaded {email_filename} ({convert_size(file_size)}) - MD5: {file_md5}")
                            #email_data = imap_server.fetch(email_id, ['RFC822.SIZE'])
                            #email_size = email_data[email_id][b'RFC822.SIZE']
                            #folder_total_size += email_size
                            #total_size += email_size
                            continue
                        logging.info(f'{email_count_format} emails downloaded in the folder »{imap_sub_folder}«.')
                time.sleep(0.8)
                delete_last_lines(1)
            except Exception as e:
                delete_last_lines(1)
                logging.error(f"Error when processing folder {decoded_folder}: {e}")
    except Exception as e:
        logging.error(f"Error when using imapclient: {e}")
    finally:
        total_email_download_format = '{:,.0f}'.format(total_email_download)
        logging.info(f"{total_email_download_format}  emails downloaded from the mailbox")
        print(f"{total_email_download_format} emails downloaded from the mailbox")
        lines += 1
        if total_email_download == total_email:
            print(f'the same number {total_email_format} of emails as was read in was also downloaded.')
            logging.info(f'the same number {total_email_format} of emails as was read in was also downloaded.')
        if total_email_download != total_email:
            print(f'There was a difference between the read {total_email_format} and downloaded {total_email_download_format} emails. Please try again.')
            logging.error(f'There was a difference between the read {total_email_format} and downloaded {total_email_download_format} emails. Please try again.')
        lines += 1
        endtime = time.time()
        duration = endtime - starttime
        durationString = formatDuration(duration)
        ## show during
        print(f"Duration of processing: {durationString}")
        logging.info(f"Duration of processing: {durationString}")
        lines += 1
        # Wait until ends
        try:
            lines += 1
            input("Press enter to exit")
        except SyntaxError:
            pass
def print_directory_tree(root, logging_file, output):
    with open(logging_file, 'a', encoding='utf-8') as f:
        f.write(f"+ {root.replace(output, '')}\n")
        for item in os.listdir(root):
            path = os.path.join(root, item)
            if os.path.isdir(path):
                print_directory_tree(path, logging_file, output)
            # else:
            #    f.write(f"  - {item.replace(email_folder_path, '')}\n")
    return

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
lines = 14
thisprogram = sys.argv[0]
file_path = os.path.realpath(thisprogram)
thisprogram = os.path.basename(file_path)
programTitle = """ ______ ______ _____         ______                       _      ______                 _ _ _____                      _                 _           
|  ____|  ____|  __ \       |  ____|                     (_)    |  ____|               (_) |  __ \                    | |               | |          
| |__  | |__  | |  | |______| |__ ___  _ __ ___ _ __  ___ _  ___| |__   _ __ ___   __ _ _| | |  | | _____      ___ __ | | ___   __ _  __| | ___ _ __ 
|  __| |  __| | |  | |______|  __/ _ \| '__/ _ \ '_ \/ __| |/ __|  __| | '_ ` _ \ / _` | | | |  | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |    | |____| |__| |      | | | (_) | | |  __/ | | \__ \ | (__| |____| | | | | | (_| | | | |__| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |   
|_|    |______|_____/       |_|  \___/|_|  \___|_| |_|___/_|\___|______|_| |_| |_|\__,_|_|_|_____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|    Version 0.2-alpha 

(C) 2023 - BrunoFischerBerlin - MIT Licence
Github: https://github.com/BrunoFischerGermany/FED-ForensicEmailDownloader
Email: info @ bruno-fischer.de
"""

example1 = f"python3 {thisprogram} --username user@example.com --password mypassword --imapurl imap.example.com --output C:\\tmp"
example2 = f"python3 {thisprogram} -u user@example.com -p mypassword -i imap.example.com -o /tmp/mails"

#############################
# Main Window
#############################
def main(output=None, username=None, password=None, imapurl=None, sslport=None, evidence=None, examiner=None, case=None):

    global lines
    usernameTestTimestamp = None
    usernameTestResult = 0
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
    if os.path.exists(pickle_file) and os.access(pickle_file, os.W_OK) and os.path.getsize(pickle_file) > 0:
        print('√ Credential File found.\n')
        with open(pickle_file, 'rb') as f:
            var_list = pickle.load(f)
        username, password, imapurl, sslport, output, examiner, case, evidence = var_list
   # Check Args found. Show and Show them.

    # check Connection to IMAP Server. If False, then check IMAPUrl, SSLPort, username and password
    if args.username:
        username = args.username
    if not username:
        username = "-empty-value-"
    if args.password:
        password = args.password
    if not password:
        password = "-empty-value-"
    if args.imapurl:
        imapurl = args.imapurl
    if imapurl == "-empty-value-" and username != "-empty-value-":
        domain = validate_email(username)
        if domain is not False:
            usernameTestTimestamp = time.time()
            usernameTestResult = 1
            imapurl, sslport = get_imap_settings(domain)
        else:
            imapurl = "-empty-value-"
    if not imapurl:
        if username != "-empty-value-":
            domain = validate_email(username)
            if domain is not False:
                usernameTestTimestamp = time.time()
                usernameTestResult = 1
                imapurl, sslport = get_imap_settings(domain)
            else:
                imapurl = "-empty-value-"
        if username == "-empty-value-":
            imapurl = "-empty-value?-"
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
        examiner = "-empty-value-"
    if args.case:
        case = args.case
    if not case:
        case = "-empty-value-"
    if args.evidence:
        evidence = args.evidence
    if not evidence:
        evidence = "-empty-value-"

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

    print("Please fill out the empty values!\n")
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
        # Check the Output Path exists and is writeable, when not, then go to stand ./
        if not os.path.exists(output) and not os.access(output, os.W_OK):
            outputPathString = "Entered Output Path is not valid, Now is Standard ./"
            output = "./"
        else:
            outputPathString = "√ Output Path is valid and exists "
        if usernameTestTimestamp is not None:
            usernameTestString = "Result: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(imapTestTimestamp))
            if usernameTestResult == 0:
                usernameTestString += " This Value is not an valid email address "
            if usernameTestResult == 1:
                usernameTestString += " This Value is an valid email address "
        else:
            usernameTestString = " This value is not tested yet "
        message = ""
        print(f'[1] Username/Email-Address:\t\t{username}\t{usernameTestString}')
        print(f'[2] Password:\t\t\t\t{password}')
        print(f'[3] IMAP-Server:\t\t\t{imapurl}')
        print(f'[4] IMAP-Server-SSL-Port:\t\t{sslport}')
        print(f'[5] Output-Path:\t\t\t{output}\t{outputPathString}')
        print(f'[6] Examiner:\t\t\t\t{examiner}')
        print(f'[7] Case:\t\t\t\t{case}')
        print(f'[8] Evicence:\t\t\t\t{evidence}')
        print(f'[C] clear credential file')
        print(f'[T] test imap credentials\t\t{imapTestString}')
        print(f'[S] save email data to output path')

        choose = input('Please select an option [1-8; S; T] (q to exit): ')
        # End loop when 'q' is entered
        if choose == 'q':
            break
        if choose.upper() == '1':
            username = input("Please enter the username/email address: ")
            domain = validate_email(username)
            if domain is not False:
                usernameTestTimestamp = time.time()
                usernameTestResult = 1
                imapurl, sslport = get_imap_settings(domain)
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
        if choose.upper() == "C":
            with open(pickle_file, "w") as f:
                f.write("")
            username = "-empty-value-"
            password = "-empty-value-"
            imapurl = "-empty-value-"
            sslport = 993
            output = "./"
            examiner = "-empty-value-"
            case = "-empty-value-"
            evidence = "-empty-value-"
        if choose.upper() == "S":
            if imapTestResult == 0:
                choose = "T"
            else:
                message = "execute export"
                export_email(username, password, imapurl, sslport, output, examiner, case, evidence, osSystem, osVersion, login_name)
        if choose.upper() == "T":
            # Check Credentials not empty!
            if(username == "-empty-value-" or password == "-empty-value-" or imapurl == "-empty-value-"):
                message = "Please check the IMAP-Credentials like Username, Password, IMAP-Server. This should not be empty!"
            else:
                # Test the Credentials
                domain = validate_email(username)
                if domain is not False:
                    usernameTestTimestamp = time.time()
                    usernameTestResult = 1
                imapTestResult, imapTestTimestamp = test_imap_credentials(imapurl, sslport, username, password)
                message = "IMAP-Credentials tested"
        if choose.upper() != "S" and choose.upper() != "T":
            with open(pickle_file, 'wb') as f:
                pickle.dump([username, password, imapurl, sslport, output, examiner, case, evidence], f)
            message = "update credential file"
            delete_last_lines(1)
        delete_last_lines(lines)
        print(f'Message: {message}\n')


if __name__ == '__main__':
    os.system('mode con: cols=180 lines=45')
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