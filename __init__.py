# Allows to be imported from another directory without fixing imports
import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
