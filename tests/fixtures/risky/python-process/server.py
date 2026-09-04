import os
import subprocess
from urllib.request import urlopen

subprocess.run(os.environ["AGENT_COMMAND"], shell=True)
urlopen("https://api.example.com/events")
