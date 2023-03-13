#./venv python3
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
import ssl
import subprocess
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

programTitle = """
 ______ ______ _____         ______                       _      ______                 _ _ _____                      _                 _           
|  ____|  ____|  __ \       |  ____|                     (_)    |  ____|               (_) |  __ \                    | |               | |          
| |__  | |__  | |  | |______| |__ ___  _ __ ___ _ __  ___ _  ___| |__   _ __ ___   __ _ _| | |  | | _____      ___ __ | | ___   __ _  __| | ___ _ __ 
|  __| |  __| | |  | |______|  __/ _ \| '__/ _ \ '_ \/ __| |/ __|  __| | '_ ` _ \ / _` | | | |  | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |    | |____| |__| |      | | | (_) | | |  __/ | | \__ \ | (__| |____| | | | | | (_| | | | |__| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |   
|_|    |______|_____/       |_|  \___/|_|  \___|_| |_|___/_|\___|______|_| |_| |_|\__,_|_|_|_____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|    Version 0.1 

(c) B. Fischer 2023"""

example1 = "python3 ForensicEmailDownloader.py --username user@example.com --password mypassword --imapurl imap.example.com --output C:\\tmp"
example2 = "python3 ForensicEmailDownloader.py -u user@example.com -p mypassword -i imap.example.com -o /tmp/mails"

def main(output=None, username=None, password=None, imapurl=None, sslport=None, evidence=None, examiner=None, case=None):
    try:
        urllib.request.urlopen('https://www.google.com', timeout=5)
        print('Internetverbindung besteht.')
    except:
        print('Es besteht keine Internetverbindung.')
        exit()

    if args.output:
        output = args.output
    else:
        output = input("Bitte geben Sie den Zielpfad ein: ")
    if not output:
        output = "./"
    if args.username:
        username = args.username
    else:
        username = input("Bitte geben Sie den Benutzernamen/die Email-Adresse ein: ")
    if args.password:
        password = args.password
    else:
        password = input("Bitte geben Sie das Passwort ein: ")
    if args.imapurl:
        imapurl = args.imapurl
    else:
        imapurl = input("Bitte geben Sie die URL zum IMAP-Server ein: ")
    if args.sslport:
        sslport = args.sslport
    else:
        sslport = input("Bitte geben Sie den Port zum IMAP-Server an (Freilassen für Standart-Port 993): ")
    if not sslport:
        sslport = 993
    if args.examiner:
        examiner = args.examiner
    else:
        examiner = input("Bitte geben Sie einen Examiner an: ")
    if args.case:
        case = args.case
    else:
        case = input("Bitte geben Sie eine Fallnummer an: ")
    if args.evidence:
        evidence = args.evidence
    else:
        evidence = input("Bitte geben Sie eine Asservatsnummer an: ")

    if os.path.exists(output) and os.access(output, os.W_OK):
        print(f'The backup path "{output}" exists and is writeable.')
        now = datetime.datetime.now()
        folder_path = os.path.join(output, now.strftime("%Y-%m-%d_%H-%M-%S"))
        # Ordner erstellen
        os.makedirs(folder_path)
        if os.path.exists(folder_path) and os.access(folder_path, os.W_OK):
            print(f'The backup path "{folder_path}" exists and is writeable.')
            output = folder_path
        else:
            print(f'The backup path "{folder_path}" could not be created.')
            exit()
    else:
        print(f'The backup path "{output}" exists and is writable.')
        exit()
    logging_file = output + '/' + now.strftime("%Y-%m-%d_%H-%M-%S") + '.txt'
    if os.path.exists(logging_file):
        print(f'The log file already {logging_file} exists and will be overwritten.')
    else:
        print(f'The log file  {logging_file} will created.')
    # leere Log-Datei erstellen
    # Infos zum Betriebssystem
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
    startText = f"""{programTitle}
Fallnummer: {case}
Asservatsnummer: {evidence}
Examiner: {examiner}

Betriebssystem: {osSystem}
Betriebssystem-Version: {osVersion}
Computer-User: {login_name}

"""

    with open(logging_file, 'w') as f:
        f.write(startText)

    logging.basicConfig(filename=logging_file, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    logging.info('Internetverbindung besteht.')
    logging.info(f'Der Sicherungspfad "{folder_path}" existiert und ist beschreibbar.')
    ssl_context = ssl.create_default_context()

    # don't check if certificate hostname doesn't match target hostname
    ssl_context.check_hostname = False

    # don't check if the certificate is trusted by a certificate authority
    ssl_context.verify_mode = ssl.CERT_NONE
    imap_server = imapclient.IMAPClient(host=imapurl, port=sslport, ssl_context=ssl_context)
    try:
        # Authentifizierung durchführen
        imap_server.login(username, password)
        email_folder_path = os.path.join(output, username)
        os.makedirs(email_folder_path, exist_ok=True)
        imap_server.select_folder('INBOX', readonly=True)
        # IMAP-Operationen durchführen

        folder_list = imap_server.list_folders()
        for folder in folder_list:
            # print(folder[2].decode())
            decoded_folder = imap_utf7.decode(folder[2])
            # decoded_folder = decoded_folder.split(' "/" ')[-1]
            # Erstellen Sie die Ordnerstruktur im Zielverzeichnis
            imap_sub_folder = os.path.join(email_folder_path, decoded_folder)
            os.makedirs(imap_sub_folder, exist_ok=True)
            logging.info(f"Ordner {imap_sub_folder} erstellt.")
            # Wähle Ordner aus
            encoded_folder = imap_utf7.encode(folder[2])
            print(imap_utf7.encode(folder[2]))
            imap_server.select_folder(imap_utf7.encode(folder[2]), readonly=True)
            # status, email_ids = imap_server.search(None, "ALL")
            # email_ids = email_ids[0].split()
            # num_emails = len(email_ids)
            # total_size = 0
            # for email_id in email_ids:
                #     status, email_data = imap_server.fetch(email_id, "(RFC822)")
                #     email_message = email.message_from_bytes(email_data[0][1])
                #     total_size += len(email_data[0][1])
            # logging.info(f"Anzahl der E-Mailsim Ordner {folder[2]}: {num_emails} ")
            # logging.info(f"Gesamtgröße der E-Mails im Ordner {folder[2]}: {total_size} Bytes")

    except Exception as e:
        logging.error(f"Fehler beim Verwenden von imapclient: {e}")
        print(f"Fehler beim Verwenden von imapclient: {e} {encoded_folder}")

    finally:
        # Verbindung zum IMAP-Server schließen
        imap_server.logout()

    # Warte auf Ende
    try:
        input("Press enter to exit")
    except SyntaxError:
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description={programTitle},
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="""Example:
{example1}
{example2}

""")
    print(f"""
{programTitle}

Github: https://github.com/BrunoFischerGermany/FED-ForensicEmailDownloader
Email: info @ bruno-fischer.de

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