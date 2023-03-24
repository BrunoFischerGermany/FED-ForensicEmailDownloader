
# FED - ForensicEmailDownloader
```
   ____                              _         ____                _    __   ___                       __                __           
  / __/ ___   ____ ___   ___   ___  (_) ____  / __/  __ _  ___ _  (_)  / /  / _ \ ___  _    __  ___   / / ___  ___ _ ___/ / ___   ____
 / _/  / _ \ / __// -_) / _ \ (_-< / / / __/ / _/   /  ' \/ _ `/ / /  / /  / // // _ \| |/|/ / / _ \ / / / _ \/ _ `// _  / / -_) / __/
/_/    \___//_/   \__/ /_//_//___//_/  \__/ /___/  /_/_/_/\_,_/ /_/  /_/  /____/ \___/|__,__/ /_//_//_/  \___/\_,_/ \_,_/  \__/ /_/V0.4-beta   
                                                                                                                                      
```

It's a Python based Forensic IMAP Download Script. 

## What should thePython script FED-ForensicEmailDownloader do?
The script can be started with commandline options. After entering the email address, it tries to retrieve the required data from the auto-conficuration database (https://autoconfig.thunderbird.net/v1.1/). 
Download all emails of the mailbox to a local folder (default is ./) while keeping the folder structure of the mailbox. 
A folder with the current timestamp is created in the local folder. The backup of the emails and a log file will be placed here. 
The email files are saved as .eml files and contain the subject in the file name. Duplicate files are incremented. 
With the commandline options rangebegin and rangeend a period can be retrieved. Note that rangeend is the same as BEFORE. That is, if you want to retrieve all emails of a year, specify --rangebegin 2022-01-01 rangeend 2023-01-01.

## Screenshot
![Model](https://raw.githubusercontent.com/BrunoFischerGermany/FED-ForensicEmailDownloader/main/programm-main.png)

## Usage/Examples

```
python3 ForensicEmailDownloader.py --username user@example.com --password mypassword --imapurl imap.example.com --output C:\\tmp --rangeend 2023-01-01
python3 ForensicEmailDownloader.py -u user@example.com -p mypassword -i imap.example.com -o /tmp/mails --rangebegin 2022-01-01

--username / -u             Username/Emai-Adress
--password / -p             Password 
--imapurl  / -i             Url to IMAP-Server
--sslport  / -s             Port for SSL on IMAP-Server
--output   / -o             Path for Folder where the data downloaded to
--examiner / -x             Name of examiner
--case     / -c             Name of case
--evidence / -e             evidence number
--rangebegin                Begin of the timerange  (YYYY-MM-DD)
--rangeend                  End of the timerange    (YYYY-MM-DD)
```
## Known Errors
- email addresses with german umlauts like ä,ö,ü in the domain are not accepted
- no 2FA

## Create an own exe
´´´pyinstaller.exe --onefile .\ForensicEmailDownloader.py --name "ForensicEmailDownloader" --icon .\favicon.ico´´´

## Malware Alert
I know this, but its a false positive for my releases. Feel free to create your own exe. see above. 

## Future
- tidy up the code
- extract date from email and set it to eml file (Creation, modification and access timestamps) 
- split log-file to log-file and a summary report
- csv file with exported eml files
- Make 2FA possible
- Maybe HTML report

## Authors

- [@BrunoFischerGermany](https://www.github.com/BrunoFischerGermany)
- [@ma-fox](https://github.com/ma-fox)

## License

[MIT](https://choosealicense.com/licenses/mit/)

