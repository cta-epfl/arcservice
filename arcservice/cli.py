import logging

from arcservice.app import app
from waitress import serve


def main():
    logging.basicConfig(level=logging.DEBUG)
    serve(app, host="0.0.0.0", port=5002)


if __name__ == "__main__":
    main()
