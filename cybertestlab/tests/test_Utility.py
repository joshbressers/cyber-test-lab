import pytest

import sys, os

myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../../')

from cybertestlab import Utility

def test_find_elfs():
    elfs = Utility.CTLUtils.find_elfs("/usr/bin")

    assert len(elfs) > 0

def test_run_command():
    command = Utility.CTLUtils.run_command("/bin/ls /dev/null", "test command")

    assert command == "/dev/null\n"

def test_which():
    which = Utility.CTLUtils.which("ls")
    assert which == "/usr/bin/ls"

def test_is_executable():
    assert Utility.CTLUtils.is_executable("/usr/bin/ls")

def test_mkdir_p():
    Utility.CTLUtils.mkdir_p("/tmp/test_dir")
    # We should end up with an exception if this fails
    assert True
