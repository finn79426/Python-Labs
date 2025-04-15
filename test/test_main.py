import os
import sys

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(f'{THIS_DIR}/../')
from src import main

def test_greeting():
    assert main.greeting("world") == "Hello world"

