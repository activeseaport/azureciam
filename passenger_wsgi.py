import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

venv_path = os.path.join(os.path.dirname(__file__), '../virtualenv/azureciam/3.9/lib/python3.9/site-packages')
sys.path.insert(1, venv_path)


from web import app as application