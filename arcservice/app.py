from contextlib import contextmanager
import json
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


try:
    __version__ = importlib.metadata.version('arcservice')
except importlib.metadata.PackageNotFoundError:
    __version__ = 'unknown'

class CertificateError(Exception):
    def __init__(self, message="invalid certificate"):
        self.message = message
        super().__init__(self.message)


# sentry_sdk.init(
#     dsn='https://452458c2a6630292629364221bff0dee@o4505709665976320' +
#         '.ingest.sentry.io/4505709666762752',
#     integrations=[
#         FlaskIntegration(),
#     ],

#     # Set traces_sample_rate to 1.0 to capture 100%
#     # of transactions for performance monitoring.
#     # We recommend adjusting this value in production.
#     traces_sample_rate=1.0,

#     release='arcservice:' + __version__,
#     environment=os.environ.get('SENTRY_ENVIRONMENT', 'dev'),
# )

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
            params={
                'service-token': service_token,
                'user': username,
                'certificate_key': 'arc',
            })

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


def parse_tabbed_output(output, levels=None):
    if levels is None:
        levels = []

    lines = output.splitlines()


    logger.debug(f"\033[32m {'.'.join(levels)}\033[0m parse_tabbed_output:")
    logger.debug("\n%s", "\n".join([">>> "+ l for l in lines]))

    result = {}
    key = None

    while lines:
        line = lines.pop(0)
        line = re.sub(r"\(.*?\)", "", line)
        
        # print(f"{len(lines):3d}:{line}")
        if re.match(r"^[a-zA-Z]", line):
            if ":" not in line:
                logger.debug("skipping non-: line %s", line)
                continue

            key, value = line.split(":", 1)
            key = re.sub("[^a-z0-9]+", "_", key.strip().lower())
            # print(key, value)

            if value.strip() != "":
                value = value.strip()
                logger.debug("key %s value %s", key, value)
            else:
                logger.debug("starting block %s", key)
                suboutput_lines = []
                while lines:
                    line = lines.pop(0)
                    logger.debug(f"{len(lines):3d}:{line}")
                    if re.match(r"^[0-9]", line):
                        line = lines.pop(0)

                    if re.match(r"^[a-zA-Z]", line):
                        logger.debug("break")
                        lines.insert(0, line)
                        break
                    
                    suboutput_lines.append(line[2:])

                value = parse_tabbed_output("\n".join(suboutput_lines), list(levels) + [key])

            if isinstance(value, dict) and "name" in value:
                key = key + "_" + re.sub("[^a-z0-9]+", "_", value.get("name").strip().lower())
                

            while key in result:
                if isinstance(value, dict):
                    key = key + "_" + value.get("name", "x")
                else:
                    key = key + "_x"

                logger.debug("key exists %s", key)

            logger.debug("\033[31mkey %s\033[0m", key)
            result[key] = value
        else:
            logger.debug("skipping line \'%s\'", line)

    return result
            

# kubectl exec -it  deployment/hub -n jh-system -- bash -c 'X509_USER_PROXY=/certificateservice-data/gitlab_ctao_volodymyr_savchenko__arc.crt arcstat -a -J -l'

def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k

        if isinstance(v, list):
            v = {str(_i): _v for _i, _v in enumerate(v)}

        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())        
        else:
            items.append((new_key, v))

    return dict(items)



def get_arcinfo_json(metrics=True):
    env = os.environ.copy()
    if 'X509_USER_PROXY' not in env:
        env['X509_USER_PROXY'] = "/certificateservice-data/gitlab_ctao_volodymyr_savchenko__arc.crt"

    result = {}

    arcinfo_output = subprocess.check_output(["arcinfo", "-l"], env=env).strip().decode()
    result["info"] = parse_tabbed_output(arcinfo_output)

    try:
        arcstat = json.loads(
            "{" + subprocess.check_output([
                "bash", "-c", "arcstat -a -J -l | grep -v WARN"
                # "bash", "-c", "kubectl exec -it  deployment/hub -n jh-system -- bash -c 'X509_USER_PROXY=/certificateservice-data/gitlab_ctao_volodymyr_savchenko__arc.crt arcstat -a -J -l' | grep -v WARN"
                ], env=env).strip().decode() + "}"
            )
    except subprocess.CalledProcessError as e:
        arcstat = {"jobs": "error"}
    
    result["njobs"] = len(arcstat["jobs"])

    psarc = subprocess.check_output(["bash", "-c", "ps aux | grep arc-h"]).strip().decode().split("\n")

    result["psn"] = len(psarc)

    # kubectl exec -it  deployment/hub -n jh-system -- bash -c 'X509_USER_PROXY=/certificateservice-data/gitlab_ctao_volodymyr_savchenko__arc.crt arcstat -a -J -l'

    # add arcstat
    # add ps aux
    # certificate number and validity
    # dcache space?

    flat_result = flatten_dict(result)

    if metrics:
        # return prometheus format
        return "\n".join([f"arcservice_{k} {v}" for k, v in flat_result.items()])
        
    else:
        return flatten_dict(result)

    # arcinfo = dict(
    #     free_slots=int(
    #         re.search(r"Free slots: ([0-9]*)", arcinfo_output.decode()).group(1)),
    #     total_slots=int(
    #         re.search(r"Total slots: ([0-9]*)",
    #                     arcinfo.decode()).group(1)),
    # )

    # return arcinfo
    

@app.route(url_prefix + '/metrics')
def metrics():
    return get_arcinfo_json(), 200


@app.route(url_prefix + '/health')
def health():
    # Find another way to check without any token

    # TODO: Use certificate from certificate service
    # with get_shared_certificate('shared::certificate')
    #      as (cert_file, cabundle_file):
    try:
        return get_arcinfo_json()


        # TODO: Check result
        # if r.stdout:
        #     return 'OK - ArcInfo with configured shared certificated is ' + \
        #         'responding', 200
        # else:
        #     logger.error('service is unhealthy: %s', r.stdout)
        #     return 'Unhealthy! - ArcInfo fails with configured shared ' + \
        #         'certificate', 500
    except subprocess.CalledProcessError as e:
        logger.error('service is unhealthy: %s', e)
        sentry_sdk.capture_exception(e)
        return 'Unhealthy! - ArcInfo fails with configured shared ' + \
            'certificate', 500


