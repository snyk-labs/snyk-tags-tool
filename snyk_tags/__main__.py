# snyk_tags/__main__.py

from snyk_tags import __app_name__, core

def main():
    core.app(prog_name=__app_name__)

if __name__ == "__main__":
    main()