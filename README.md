
# FED - ForensicEmailDownloader
```
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+
 |F|o|r|e|n|s|i|c|E|m|a|i|l|D|o|w|n|l|o|a|d|e|r| |V|0|.|4|-|b|e|t|a|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ 
```

It's a Python based Forensic IMAP Download Script. 

## Screenshot
![Model](https://raw.githubusercontent.com/BrunoFischerGermany/FED-ForensicEmailDownloader/main/programm-main.png)

## Usage/Examples

```
python3 ForensicEmailDownloader.py --username user@example.com --password mypassword --imapurl imap.example.com --output C:\\tmp
python3 ForensicEmailDownloader.py -u user@example.com -p mypassword -i imap.example.com -o /tmp/mails

--username / -u             Username/Emai-Adress
--password / -p             Password 
--imapurl  / -i             Url to IMAP-Server
--sslport  / -s             Port for SSL on IMAP-Server
--output   / -o             Path for Folder where the data downloaded to
--examiner / -x             Name of examiner
--case     / -c             Name of case
--evidence / -e             evidence number
--rangebegin                Begin of the timerange
--rangeend                  End of the timerange
```
## Known Errors
- email addresses with german umlauts like ä,ö,ü in the domain are not accepted
- no 2FA

## Future
- tidy up the code
- split log-file to log-file and report
- Make 2FA possible

## Authors

- [@BrunoFischerGermany](https://www.github.com/BrunoFischerGermany)
- [@ma-fox](https://github.com/ma-fox)

## License

[MIT](https://choosealicense.com/licenses/mit/)

