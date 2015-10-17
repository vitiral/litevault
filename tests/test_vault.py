import os
import time
import string
import json
import tempfile
import subprocess
from unittest import TestCase
from threading import Thread
from mock import patch
import litevault

test_special_chars = tuple(c for c in litevault.x_special_char_mappings if c not in {'\n'})

passwords = {
    'citi': {
        'u': 'mynameisbob',
        'p': 'save me charlie 43',
        'i': 'this is a bank',
        'v': litevault.__version__,
    },
    'gmail': {
        'u': 'user@gmail.com',
        'p': 'the best password',
        'i': 'my email! whooo!',
        'v': litevault.__version__,
    },
    'supertest': {
        'u': 'I have a user',
        'p': 'special_chars: ' + ' '.join(string.ascii_letters + string.punctuation),
        'i': 'I have created\nthe ultimate\npassword',
        'v': litevault.__version__,
    }
}

class DefaultArgs(object):
    file = None
    timeout = 8
    editor = None
    merge = False
    send_stored_pass = False
    keypress_delay_us = 50
    wait = 0.05
    password = 'hello'
    test = False


class TestVault(TestCase):
    def test_load_dump(self):
        with tempfile.NamedTemporaryFile('wb+') as f:
            vault = litevault.Vault(f.name, 'hello', maxtime=0.01, initial_data=passwords)
            assert vault == passwords

            # data not actually saved yet. Save it and reload it
            vault.save()
            vault._load_passwords()
            assert vault == passwords

            # Make sure that data is jumbled
            f.seek(0)
            encrypted = f.read()
            with self.assertRaises(UnicodeDecodeError):
                encrypted.decode()

def send_keypresses_thread(keys, wait=0.1):
    th = Thread(target=litevault.send_keypresses, args=(keys, 2000, wait))
    th.start()
    return th

def fill_app_thread(passwords, wait=0.1):
    def fill_app():
        time.sleep(wait)
        for key, value in passwords.items():
            litevault.send_keypresses('c {}\n'.format(key) )
            time.sleep(0.2)
            litevault.send_keypresses(value.get('u', '') + '\n' )
            time.sleep(0.2)
            litevault.send_keypresses(value.get('p', '') + '\n')
            time.sleep(0.2)
            info = value.get('i', '')
            if info:
                litevault.send_keypresses(info + '\n')
                time.sleep(0.4)
                subprocess.call('xdotool keydown control key d keyup control'.encode().split())
            time.sleep(0.5)
    th = Thread(target=fill_app)
    th.start()
    return th

@patch.object(litevault, 'quit_app', return_value=Exception)
class TestApp(TestCase):
    def setUp(self):
        litevault.kill = False
        litevault.args = DefaultArgs()
        fno, fpath = tempfile.mkstemp()
        os.remove(fpath)
        litevault.args.file = fpath

    def tearDown(self):
        litevault.kill = True
        os.remove(litevault.args.file)

    def test_load_password(self, quit_app):
        '''Intrinsically tests save password from setUp as well as the use of the automated
            key presses'''
        fill_app_thread(passwords, wait=0.5)
        send_keypresses_thread('p citi\n', wait=10)
        vault = litevault.main(1 + len(passwords))
        assert litevault.curpass == passwords['citi']['p']
        for value in vault.values():
            value.pop('t')
        assert vault == passwords
