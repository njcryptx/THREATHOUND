import os
import sys
import subprocess
import shutil

def main():
    if os.geteuid() != 0:
        print("Error: Requires sudo privileges", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
