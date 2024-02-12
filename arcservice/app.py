from contextlib import contextmanager
import os
import re
import requests
import secrets
import stat
import subprocess
import tempfile
import importlib.metadata
from flask import Flask
from flask_cors import CORS

import logging

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration


class CertificateError(Exception):
    def __init__(self, message="invalid certificate"):
        self.message = message
        super().__init__(self.message)


sentry_sdk.init(
    dsn='https://452458c2a6630292629364221bff0dee@o4505709665976320' +
        '.ingest.sentry.io/4505709666762752',
    integrations=[
        FlaskIntegration(),
    ],

    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0,

    release='arcservice:' + importlib.metadata.version("arcservice"),
    environment=os.environ.get('SENTRY_ENVIRONMENT', 'dev'),
)

# from flask_oidc import OpenIDConnect
logger = logging.getLogger(__name__)


def urljoin_multipart(*args):
    """Join multiple parts of a URL together, ignoring empty parts."""
    logger.info('urljoin_multipart: %s', args)
    return '/'.join(
        [arg.strip('/')
         for arg in args if arg is not None and arg.strip('/') != '']
    )


url_prefix = os.getenv('JUPYTERHUB_SERVICE_PREFIX', '').rstrip('/')


def create_app():
    app = Flask(__name__)
    CORS(app)

    app.config['SECRET_KEY'] = os.environ.get(
        'FLASK_SECRET', secrets.token_bytes(32))
    app.secret_key = app.config['SECRET_KEY']

    app.config['CTACS_URL'] = os.getenv('CTACS_URL', '')

    return app


app = create_app()


@app.errorhandler(CertificateError)
def handle_certificate_error(e):
    sentry_sdk.capture_exception(e)
    return e.message, 400


@contextmanager
def get_shared_certificate(user=None):
    with tempfile.TemporaryDirectory() as tmpdir:
        if user is None:
            raise Exception("Missing user")

        service_token = os.environ['JUPYTERHUB_API_TOKEN']
        username = user
        if isinstance(user, dict):
            username = user['name']

        r = requests.get(
            urljoin_multipart(os.environ['CTACS_URL'], '/certificate'),
            params={'service-token': service_token, 'user': username})

        if r.status_code != 200:
            logger.error(
                'Error while retrieving certificate : %s', r.content)
            raise CertificateError(
                f"Error while retrieving certificate: {r.text}")

        cert_file = os.path.join(tmpdir, 'certificate')
        cabundle_file = os.path.join(tmpdir, 'cabundle')
        with open(cert_file, 'w') as f:
            f.write(r.json().get('certificate'))
        os.chmod(cert_file, stat.S_IRUSR)
        with open(cabundle_file, 'w') as f:
            f.write(r.json().get('cabundle'))
        os.chmod(cabundle_file, stat.S_IRUSR)

        yield cert_file, cabundle_file


@app.route(url_prefix + '/health')
def health():
    # Find another way to check without any token

    # TODO: Use certificate from certificate service
    # with get_shared_certificate('shared::certificate')
    #      as (cert_file, cabundle_file):
    try:
        r = subprocess.run(['ls', '-l'], stdout=subprocess.PIPE)
        arcinfo = subprocess.check_output(["arcinfo", "-l"]).strip()
        arcinfo = dict(
            free_slots=int(
                re.search(r"Free slots: ([0-9]*)", arcinfo.decode()).group(1)),
            total_slots=int(
                re.search(r"Total slots: ([0-9]*)",
                          arcinfo.decode()).group(1)),)

        # TODO: Check result
        if r.stdout:
            return 'OK - ArcInfo with configured shared certificated is ' + \
                'responding', 200
        else:
            logger.error('service is unhealthy: %s', r.stdout)
            return 'Unhealthy! - ArcInfo fails with configured shared ' + \
                'certificate', 500
    except subprocess.CalledProcessError as e:
        logger.error('service is unhealthy: %s', e)
        sentry_sdk.capture_exception(e)
        return 'Unhealthy! - ArcInfo fails with configured shared ' + \
            'certificate', 500
