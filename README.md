# pseudo-stealer

**WARNING: This script is a fully disarmed version of a real info stealer. It is for educational and research purposes only.**

## What is this?
This script is a heavily modified and disarmed version of a real-world info stealer malware. All exfiltration (sending data to attackers) and destructive/system-tampering actions have been neutralized. The script now only collects data locally, zips it, and prints out what would have been stolen, along with debug information.

## What does it do?
- Simulates the collection of sensitive files, browser cookies, Discord tokens, Roblox cookies, wallet files, clipboard, screenshots, and more.
- Zips up the collected data in a temporary directory.
- **Does NOT send, upload, or exfiltrate any data.**
- Prints a warning and the path to the zip file, so you can see what would have been stolen.
- Prints debug information for each step.

## Safety Precautions
- **No data leaves your machine.** All network exfiltration code is disabled.
- All destructive/system-tampering actions (like disabling Defender, killing processes, deleting files) are replaced with print statements.
- The script still accesses your local files and may display sensitive information in the console and in the zip file it creates.
- **Run only in a safe, controlled environment.**
- Review the code before running if you have any concerns.

## Usage
1. Install the required Python dependencies (see below).
2. Run the script with Python 3 on Windows:
   ```
   python main1.py
   ```
3. The script will print debug information and the path to the zip file containing the simulated "stolen" data.
4. Inspect the zip file to see what would have been stolen by the original malware.

## Dependencies
- Python 3.8+
- `requests`, `pyperclip`, `psutil`, `Pillow`, `pycountry`, `browser_cookie3`, `pycryptodome`, `concurrent.futures`, `win32crypt`

Install dependencies with:
```
pip install requests pyperclip psutil Pillow pycountry browser_cookie3 pycryptodome pypiwin32
```

## Disclaimer
This script is for educational and research purposes only. Do not use it for malicious purposes. The authors and modifiers of this script are not responsible for any misuse or damage caused by running this code.
