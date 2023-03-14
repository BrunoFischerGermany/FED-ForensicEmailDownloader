
# FED - ForensicEmailDownloader
```
 ______ ______ _____         ______                       _      ______                 _ _ _____                      _                 _           
|  ____|  ____|  __ \       |  ____|                     (_)    |  ____|               (_) |  __ \                    | |               | |          
| |__  | |__  | |  | |______| |__ ___  _ __ ___ _ __  ___ _  ___| |__   _ __ ___   __ _ _| | |  | | _____      ___ __ | | ___   __ _  __| | ___ _ __ 
|  __| |  __| | |  | |______|  __/ _ \| '__/ _ \ '_ \/ __| |/ __|  __| | '_ ` _ \ / _` | | | |  | |/ _ \ \ /\ / / '_ \| |/ _ \ / _` |/ _` |/ _ \ '__|
| |    | |____| |__| |      | | | (_) | | |  __/ | | \__ \ | (__| |____| | | | | | (_| | | | |__| | (_) \ V  V /| | | | | (_) | (_| | (_| |  __/ |   
|_|    |______|_____/       |_|  \___/|_|  \___|_| |_|___/_|\___|______|_| |_| |_|\__,_|_|_|_____/ \___/ \_/\_/ |_| |_|_|\___/ \__,_|\__,_|\___|_|    Version 0.1 
```

It's a Python based IMAP Download Script. 

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
```
## Authors

- [@BrunoFischerGermany](https://www.github.com/BrunoFischerGermany)

- [@ma-fox](https://github.com/ma-fox)
## License

[MIT](https://choosealicense.com/licenses/mit/)

