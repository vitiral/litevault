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
    maxtime = 0.01
    maxmem = 16


class TestVault(TestCase):
    @staticmethod
    def get_vault(path, passwords):
        vault = litevault.Vault(path, 'hello', maxtime=0.01, maxmem=16,
                                initial_data=passwords)
        assert vault == passwords
        return vault

    def test_load_dump(self):
        with tempfile.NamedTemporaryFile('wb+') as f:
            vault = self.get_vault(f.name, passwords)

            # data not actually saved yet. Save it and reload it
            vault.save()
            vault._load_passwords()
            assert vault == passwords

            # Make sure that data is jumbled
            f.seek(0)
            encrypted = f.read()
            with self.assertRaises(UnicodeDecodeError):
                encrypted.decode()

    def test_merge(self):
        fno, fpath = tempfile.mkstemp()
        fno2, fpath2 = tempfile.mkstemp()
        os.remove(fpath)
        os.remove(fpath2)
        pw1 = {
            'from1': {'u': '1', 't': 1},
            'changeme': {'u': 'do not have this', 't': 1},
        }
        pw2 = {
            'from2': {'u': '2', 't': 1},
            'changeme': {'u': 'have this', 't': 2},
        }
        v = self.get_vault(fpath, pw1)
        v.save()
        v = self.get_vault(fpath2, pw2)
        v.save()
        args = DefaultArgs()
        args.file = fpath
        args.merge = fpath2
        result = litevault.merge_vaults(args)
        expected = {
            'from1': {'u': '1', 't': 1},
            'from2': {'u': '2', 't': 1},
            'changeme': {'u': 'have this', 't': 2},
        }
        assert result == expected
        os.remove(fpath)
        os.remove(fpath2)


def send_keypresses_thread(keys, wait=0.1):
    th = Thread(target=litevault.send_keypresses, args=(keys, 2000, wait))
    th.start()
    return th

def run_keypresses_thread(passwords=None, extra=None, wait=0.1):
    extra = extra or []
    def fill_app():
        time.sleep(wait)
        for key, value in passwords.items():
            litevault.send_keypresses('c {}\n'.format(key) )
            litevault.send_keypresses(value.get('u', '') + '\n' )
            litevault.send_keypresses(value.get('p', '') + '\n')
            info = value.get('i', '')
            if info:
                litevault.send_keypresses(info + '\n')
                time.sleep(0.1)
                subprocess.call('xdotool keydown control key d keyup control'.encode().split())
            time.sleep(0.1)

        for e in extra:
            litevault.send_keypresses(e)
            time.sleep(0.1)

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
        extra = [
            'p citi\n',
        ]
        run_keypresses_thread(passwords, extra=extra, wait=0.5)
        vault = litevault.main(1 + len(passwords))
        assert litevault.curpass == passwords['citi']['p']
        for value in vault.values():
            value.pop('t')
        assert vault == passwords
