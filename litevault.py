#!/usr/bin/python
''' litevault - a lightweight password manager written in pure python
'''
from __future__ import print_function

import os
import sys
import re
import json
import time
import datetime
import tempfile
import random
import string
import getpass
import subprocess
import signal
import select
import argparse

import scrypt

__version__ = '0.0.4'

# Python 2 & 3 compatibility
if sys.version_info[0] == 2:
    input = raw_input

# Global current stored password
curpass = ''
args = None
kill = False

##################################################
# Constants

MEGABYTE = 1048576
pid_file = '/tmp/litevault.pid'
intro_msg = r'''
 ************************************
 *       /-------\  Type "?" or "h" *
 *  lite | vault |     for help.    *
 *       \-------/                  *
 ************************************'''
help_msg = '''\
Help:
h or ?         = help
q or exit      = quit litevault
L              = lock litevault (same as if it timed out)
n              = set new password for vault (and save it to disk)
t              = set new timeout password
l or ls     [] = list items. Add an item to do a fuzzy search
c or mk     [] = create/overwrite item in vault
d or rm     [] = delete data from vault
m or mv     [] = move item to new key
e           [] = edit info in editor (slightly less secure, see docs)
u           [] = get user
p           [] = get password
i           [] = get info
a           [] = get user + password and show info
[NON-MATCHING] = same as "a [NON-MATCHING]". Happens when item doesn't match any commands
'''
TIMEOUT_PWD_KEY='__litevault_timeout_password__'


##################################################
# X keboard automation mappings
# http://www.linux.org/threads/xdotool-keyboard.6414/

shift_c = 'keydown Shift_L\nusleep 50\nkey {}\nusleep 50\nkeyup Shift_L'.format

x_special_char_mappings = {
    '~': shift_c('quoteleft')            , '!': shift_c('1')            ,
    '@': shift_c('2')                    , '#': shift_c('3')            ,
    '$': shift_c('4')                    , '%': shift_c('5')            ,
    '^': shift_c('6')                    , '&': shift_c('7')            ,
    '*': shift_c('8')                    , '(': shift_c('9')            ,
    ')': shift_c('0')                    , ':': shift_c('semicolon')    ,
    '_': shift_c('minus')                , '+': shift_c('equal')        ,
    '{': shift_c('bracketleft')          , '}': shift_c('bracketright') ,
    '|': shift_c('backslash')            , '"': shift_c('quoteright')   ,
    '<': shift_c('comma')                , '>': shift_c('period')       ,
    '?': shift_c('slash')                ,
    '\n': 'keydown Return\nusleep 50\nkeyup Return' ,
}

x_char_mappings = {
    "`": 'quoteleft'   ,
    '-': 'minus'       , '=': 'equal'        ,
    '[': 'bracketleft' , ']': 'bracketright' ,
    '\\': 'backslash'  , ';': 'semicolon'    ,
    "'": 'quoteright'  , ',': 'comma'        ,
    '.': 'period'      , '/': 'slash'        ,
    ' ': 'space'       , '\t': 'Tab'         ,
}


def send_keypresses(characters, delay_us=10000, wait=0):
    '''Send a sequence of keypresses to the keyboard.

    This function is intended to be secure -- as in outside processes should not be
    able to see what it is doing.

    :characters: characters to send
    :delay_us: delay in microseconds between each keypress
    '''
    time.sleep(wait)
    keypresses = []
    for c in characters:
        if c in x_special_char_mappings:
            keypresses.append(x_special_char_mappings[c])
        elif c in x_char_mappings:
            keypresses.append('key ' + x_char_mappings[c])
        elif c in string.ascii_uppercase:
            keypresses.append(shift_c(c))
        else:
            keypresses.append('key ' + c)
    keypresses_bytes = '\nusleep {}\n'.format(delay_us).join(keypresses).encode() + b'\n'
    sh = subprocess.Popen(['xte'], stdin=subprocess.PIPE)
    # print("Sending keypresses {}\n{!r}".format(keypresses, keypresses_bytes))
    sh.communicate(input=keypresses_bytes)


##################################################
# Convenience Functions

def get_keys(dictionary, keys):
    return {k: dictionary[k] for k in keys}

def set_password_dialog(first_message="New Password: "):
    while True:
        p1 = getpass.getpass(first_message)
        if not p1:
            print("No password receiving, skipping")
            return None
        p2 = getpass.getpass("Enter the same password: ")
        if p1 == p2:
            return p1
        else:
            print("Passwords don't match. Retrying...")


def print_item_not_found(item):
    print("Item not found {}".format(item))


def pplist(l, cols=4, indent=0):
    if not isinstance(l, list):
        l = list(l)
    while len(l) % cols != 0:
        l.append(" ")
    step = len(l) // cols
    step = step if step != 0 else 1
    split = [l[i:i + len(l) // cols] for i in range(0, len(l), step)]
    for row in zip(*split):
        print(' ' * indent + "".join(str.ljust(i, 20) for i in row))


def clear_screen(wait=True):
    out = ''
    if wait:
        if wait is True:
            wait = '\n ** Press ENTER to clear the screen **'
        out = input(wait)
    print('\x1b[0;0H\x1b[2J\n' + intro_msg)
    return out


def output_password(signum, stack):
    '''Output the password on the keyboard'''
    if not curpass:
        return
    send_keypresses(curpass, args.keypress_delay_us)


def verify_environment():
    requirements = {
        "xautomation: need xte": 'xte -h',
    }
    for r, cmd in requirements.items():
        try:
            subprocess.check_output(cmd.encode().split())
        except Exception as E:
            quit_app('!! Dependency not met: {} !!'.format(r), rc=1)


def input_text(msg='', previous='', use_editor=False):
    print(msg)
    if not use_editor:
        print(" ** Press Cntrl+D to finish, e to edit with {}".format(args.editor) +
              " or ENTER to skip")
        text = [input("> ")]
        if not text[0]:
            return ''
    if use_editor or text[0] == 'e':
        fno, path = tempfile.mkstemp(dir='/dev/shm')
        try:
            with open(path, 'w') as f:
                f.write(previous)
            os.fsync(fno)
            subprocess.call('{} {}'.format(args.editor, f.name), shell=True)
            os.fsync(fno)
            with open(path, 'r') as f:
                return f.read().strip()
        finally:
            os.remove(path)
    while True:
        try:
            text.append(input('> '))
        except EOFError:
            return '\n'.join(text).strip()


def generate_password(length):
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    random.seed = (os.urandom(1024))
    return ''.join(random.choice(chars) for i in range(length))


def quit_app(msg=None, rc=0):
    print(msg or " ** Quitting litevault **")
    sys.exit(rc)


##################################################
# Vault Class

class Vault(dict):
    """Safe password storage and retrieval"""

    def __init__(self, path, password, maxtime=0.5, maxmem=256, initial_data=None):
        """
        :path: path to vault file
        :password: password to open file
        """
        self.path = path
        self.password = password
        self.maxtime = maxtime
        self.maxmem = maxmem
        if initial_data:
            dict.__init__(self, initial_data)
        else:
            dict.__init__(self)
            self._load_passwords()

    def _load_passwords(self):
        if not os.path.exists(self.path):
            self.clear()
            return
        with open(self.path, 'rb') as f:
            encrypted = f.read()
        text = scrypt.decrypt(encrypted, self.password, maxtime=self.maxtime * 20, maxmem=self.maxmem * 4 * MEGABYTE, maxmemfrac=50)
        data = json.loads(text)
        self.clear()
        self.update(data)

    def _dump_passwords(self, passwords=None):
        if passwords is not None:
            self.clear()
            self.update(passwords)
        text = json.dumps(self)
        encrypted = scrypt.encrypt(text, self.password, maxtime=self.maxtime, maxmem=self.maxmem * MEGABYTE, maxmemfrac=50)
        with open(self.path, 'wb') as f:
            f.write(encrypted)

    def save(self, passwords=None):
        self._dump_passwords(passwords)



##################################################
# User Functions

# Loading and Viewing

def load_info(vault, item):
    if item not in vault:
        print_item_not_found(item)
        return
    value = vault[item]
    ts = value.get('t', None)
    ts = datetime.datetime.fromtimestamp(ts) if ts else 'unknown'
    print('\n ** Info on {}**\n* username: {}\nstored time: {}\n* Info: \n{}'.format(
          item, value.get('u'), str(ts), value.get('i')))
    clear_screen()


def load_password(vault, item, append=False):
    if item not in vault:
        print_item_not_found(item)
        return
    global curpass
    value = vault[item]
    key = 'p' if 'p' in value else 'password' if 'password' in value else None
    if key is None:
        print('!! no password for {} !!'.format(item))
        curpass = ''
        return
    if append:
        curpass += '\t' + value[key] + '\n'
    else:
        curpass = value[key]
    print("  Password ready for: {}".format(item))


def load_user(vault, item):
    if item not in vault:
        print_item_not_found(item)
        return
    global curpass
    value = vault[item]
    if value is None:
        return
    key = 'u' if 'u' in value else 'username' if 'username' in value else None
    if key is None:
        print('!! no username for {} !!'.format(item))
        curpass = ''
        return
    curpass = value[key]
    print("  Username ready for: {}".format(item))


def load_all(vault, item):
    if item not in vault:
        print_item_not_found(item)
        return
    load_user(vault, item)
    load_password(vault, item, append=True)
    load_info(vault, item)


def list_items(vault, item=None):
    print('\n ** Items **')
    if item is None:
        items = list(vault)
    else:
        pat = re.compile(r'.*?'.join(item))
        items = [i for i in vault if pat.search(i)]
    items = sorted(i for i in items if i not in {TIMEOUT_PWD_KEY})
    pplist(items)
    user_input = clear_screen("command: ")
    execute_command(vault, user_input)


# Creating, Deleting, and Saving

def edit_info(vault, item):
    previous = vault[item].get('i', '') if item in vault else ''
    info = input_text("** Editing info with editor **", previous, use_editor=True)
    vault[item] = info
    save_vault()


def create_item(vault, item):
    quit_msg = "Got 'q' -- Quiting"
    print(" ** Type in the value for each.                                               **\n"
          " ** To skip a field (and not change it), press ENTER without typing anything. **\n"
          " ** To quit (and not store) type q for any field.                             **")
    if item in vault:
        print("!! WARNING: {} already exists in vault, !!\n".format(item) +
              "!! any non-skipped items will be overwritten !!")
    username = input("username: ")
    if username == 'q':
        print(quit_msg)
        return
    print(" ** Enter password. Enter g [number] to generate a random password **\n"
          " ** of length `number` (defaults to 32 if no input specified)      **")
    password = getpass.getpass("password: ")
    if password == 'q':
        print(quit_msg)
        return
    if password[0:2].strip() == 'g':
        # Generate password
        length = password[2:]
        if length:
            # if length isn't valid, re-ask until it is
            while True:
                try:
                    length = int(length)
                    break
                except ValueError:
                    print("!! length must be integer, got: [{}] !!".format(length))
                    length = input("length: ").strip()
                    if length == 'q':
                        print(quit_msg)
                        return
        else:
            length = 32
        password = generate_password(length)

    current_info = vault[item].get('i', '') if item in vault else ''
    info = input_text("** info:", current_info)
    if info == 'q':
        print(quit_msg)
        return
    if not (username or password or info):
        return
    load = False
    if item not in vault:
        vault[item] = {}
    value = vault[item]
    if username:
        value['u'] = username
    if password:
        value['p'] = password
        value['v'] = __version__
        load = True
    if info:
        value['i'] = info
    value['t'] = time.time()
    clear_screen(False)
    print(" ** Stored {} **".format(item))
    vault.save()
    print("Vault Saved")
    if load:
        print(" ** Loading new password **")
        load_password(vault, item)


def save_vault(vault):
    vault.save()
    print(" ** Vault Saved **")


def delete_item(vault, item):
    if item not in vault:
        print("Item {} not in vault".format(item))
        return
    if input("Would you really like to delete {}? (y/n)".format(item)).lower()[:1] in ('n', ''):
        print("Not deleting")
        return
    vault.pop(item)
    print("Deleted {} ".format(item))


def move_item(vault, item):
    newitem = input("New name for {}: ".format(item)).strip()
    if newitem in vault:
        print("!! {} already in vault. Delete or move that item first !!")
        return
    vault[newitem] = vault.pop(item)
    save_vault(vault)


def new_password(vault, *args):
    newpass = set_password_dialog("Enter new vault password: ")
    if not newpass:
        print("No password entered, skipping")
        return
    vault.save()
    vault.password = newpass
    save_vault(vault)


def set_timeout_pwd(vault, *args):
    tpass = set_password_dialog("Enter new timeout password: ")
    if not tpass:
        print("No password entered, doing nothing.")
        return
    vault[TIMEOUT_PWD_KEY] = tpass
    save_vault(vault)


# Other User Functions

def execute_command(vault, user_input):
    if not user_input:
        return
    print_help = lambda vault, item: print(help_msg)
    interface = {
        # global actions
        '?': print_help,    'h': print_help,
        'n': new_password,
        't': set_timeout_pwd,
        # actions on items
        'l': list_items,    'ls': list_items,
        'c': create_item,   'mk': create_item,
        'd': delete_item,   'rm': delete_item,
        'm': move_item,     'mv': move_item,
        'e': edit_info,
        'u': load_user,
        'p': load_password,
        'i': load_info,
        'a': load_all,
    }
    user_input = user_input.split()
    cmd = user_input[0]
    if cmd not in interface:
        cmd = 'a'
        item = ' '.join(user_input)
        print("Defaulting to command 'a'")
    else:
        item = ' '.join(user_input[1:]) if len(user_input) > 1 else None
    return interface[cmd](vault, item)


def timeout_loop(vault, locked=False):
    global curpass
    curpass = ''
    clear_screen(False)
    if locked:
        print(" ** litevault locked. Buffered password cleared    **")
    else:
        print(' ** litevault timed out. Buffered password cleared **')
    print(" ** 'q' will still quit                            ** ")
    timeout_pwd = vault.get(TIMEOUT_PWD_KEY)
    msg = "Enter vault password: " if not timeout_pwd else "Enter vault or timeout password: "
    for n in range(3):
        pwd = getpass.getpass(msg)
        if pwd == 'q':
            quit_app()
        if pwd == vault.password or pwd == timeout_pwd:
            return
        time.sleep(1)
        print("!! Incorrect password attempt {} out of 3 !!".format(n+1))
    quit_app("!! Incorrect password 3 times, exiting !!", rc=1)


##################################################
# App Functions

def merge_vaults(path1, path2):
    ''' Merge two vaults together using timestamps to determine which keys to keep '''
    print("** Enter password for vault1. This is the password that will be used **\n"
          "** for the new vault **")
    msg = "Password for {}: ".format(path1)
    main_pwd = getpass.getpass(msg.format(path1))
    vault1 = Vault(path1, main_pwd)
    try:
        vault2 = Vault(path2, main_pwd)
    except scrypt.error:
        pwd = getpass.getpass(msg.format(path2))
        vault2 = Vault(path2, pwd)
    vault = Vault(args.file, main_pwd)
    # get keys that are in both
    v1_keys = set(vault1).difference(vault2)
    v2_keys = set(vault2).difference(vault1)
    print("using vault 1 for:", v1_keys)
    print("using vault 2 for:", v2_keys)
    vault.update(get_keys(vault1, v1_keys))
    vault.update(get_keys(vault2, v2_keys))
    for key in set(vault1).intersection(vault2):
        ts1 = vault1[key].pop('t', 0)
        ts2 = vault2[key].pop('t', 0)
        if ts1 == ts2:
            print(" ** timestamps for {} are identical. **")
            while True:
                value = input("Which vault (1 or 2):")
                try:
                    value = int(value)
                    if value in (1, 2):
                        break
                except ValueError:
                    pass
            ts1 = ts2 + 1 if value == 1 else ts2 - 1
        if ts1 > ts2:
            print(" ** using vault1 for {} **".format(key))
            vault[key] = vault1[key]
        elif ts1 < ts2:
            print(" ** using vault2 for {} **".format(key))
            vault[key] = vault2[key]
    save_vault(vault)
    print(" ** Successfully merged and saved new vault. Exiting ** ")


def parse_args():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', default='~/.vault',
                        help='password file to load. Default is ~/.vault')
    parser.add_argument('-t', '--timeout', default=60, type=float,
                        help='time in seconds before program is locked if there is no activity (default=60).'
                              '. It is recommended to set a "timeout password" with the "t" command')
    parser.add_argument('-e', '--editor', help="Editor to use for info screen. This should be opened in"
                                               " 'secure mode'. See README.")
    parser.add_argument('-m', '--merge', nargs='+', help="input two vaults to merge based on timestamps")
    parser.add_argument('--maxtime', default=0.5, type=float, help=
        "the maxtime to send to scrypt. This is the maximum amount of time it will take to encrypt"
        " the passwords on your system.")
    parser.add_argument('--maxmem', default=256, type=int, help=
        "the maxmem to send to scrypt in MB. This is the maximum amount of memory for scrypt to use when"
        " encrypting/decrypting")
    parser.add_argument('-s', '--send_stored_pass', action='store_true',
                        help="bind this to a keyboard shortcut to send password through keyboard")
    parser.add_argument('-k', '--keypress_delay_us', default=10000, type=int,
                        help='time in micro-seconds to delay between each keypress when entering passwords')
    parser.add_argument('-w', '--wait', default=0.25, help="Wait time before sending the stored password")
    parser.add_argument('-p', '--password', help='Use only in testing, not secure!')
    parser.add_argument('--test', action='store_true', help='used for testing')
    args = parser.parse_args()
    verify_environment()
    if args.send_stored_pass:
        with open(pid_file, 'rb') as f:
            pid = int(f.read())
        time.sleep(args.wait)
        subprocess.check_output('kill -10 {}'.format(pid).encode(), shell=True)
        sys.exit()
    if args.merge:
        merge_vaults(*args.merge)
        quit_app()
    args.editor = args.editor or os.environ['EDITOR'] or 'nano'
    safe_editor_versions = {
        'nano': 'nano -R',      # -R = restricted mode (default)
        'vim': 'vim -Zu NONE',  # -Z = restricted mode, -u NONE = don't load plugins
        'emacs': 'emacs -nw -q -nl -nsl',  # terminal mode, no init file, no shared mem, no-site-lisp
    }
    if args.editor in safe_editor_versions:
        args.editor = safe_editor_versions[args.editor]
    path = os.path.abspath(os.path.expanduser(args.file))
    if not os.path.exists(path):
        print("No vault file at {} -- initializing empty vault".format(args.file))
    args.file = path
    if not args.password:
        msg = "Password for {}: ".format(args.file)
        if not os.path.exists(path):
            args.password = set_password_dialog(msg)
        else:
            args.password = getpass.getpass(msg)
    return args


def main(loops=None):
    global args
    signal.signal(signal.SIGINT, lambda *a: quit_app("\n ** Received Cntrl+C, quitting **"))
    if not args:
        args = parse_args()
    vault = Vault(path=args.file, password=args.password, maxtime=args.maxtime, maxmem=args.maxmem)
    signal.signal(signal.SIGUSR1, output_password)
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    if args.test:
        load_password(vault, 'hello')
        output_password(None, None)
        return
    print(intro_msg)
    while loops is None or loops:
        loops = None if loops is None else loops - 1
        print("command: \rcommand: ", end='')
        i, o, e = select.select([sys.stdin], [], [], args.timeout)
        if kill:
            return
        if not i:
            timeout_loop(vault)
            continue
        user_input = sys.stdin.readline().strip()
        if user_input == 'L':
            timeout_loop(vault, locked=True)
            continue
        if user_input in {'q', 'exit'}:
            quit_app()
        try:
            execute_command(vault, user_input)
        except (SystemExit, EOFError):
            pass
    return vault


if __name__ == '__main__':
    main()
