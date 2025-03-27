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
from collections import defaultdict
from datetime import datetime, timedelta

import logging

import sentry_sdk
# from sentry_sdk.integrations.flask import FlaskIntegration


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
    logger.debug("\n%s", "\n".join([">>> " + line for line in lines]))

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

                value = parse_tabbed_output(
                    "\n".join(suboutput_lines),
                    list(levels) + [key])

            if isinstance(value, dict) and "name" in value:
                key = key + "_" + re.sub("[^a-z0-9]+",
                                         "_",
                                         value.get("name").strip().lower())

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


def refresh_oidc_token():
    refresh_token = os.environ.get('DCACHE_REFRESH_TOKEN', None)
    client_secret = os.environ.get('DCACHE_CLIENT_SECRET', None)
    if refresh_token is None:
        logger.error('DCACHE_REFRESH_TOKEN env var is not set')
        return None
    if client_secret is None:
        logger.error('DCACHE_CLIENT_SECRET env var is not set')
        return None
    token_url = 'https://keycloak.cta.cscs.ch/realms/master/protocol/openid-connect/token'
    data = {
    'grant_type': 'refresh_token',
    'client_id': "dcache-cta-cscs-ch-users",
    'client_secret': client_secret,
    'refresh_token': refresh_token
    }
    response = requests.post(token_url, data=data)
    new_access_token = None
    if response.status_code == 200:
        token_data = response.json()
        new_access_token = token_data.get('access_token')
        
        # Optional: sometimes a new refresh token is returned
        new_refresh_token = token_data.get('refresh_token')
        if new_refresh_token:
            os.environ['DCACHE_REFRESH_TOKEN'] = new_refresh_token
    else:
        logger.error(f"Error refreshing token: {response.status_code}\n{response.json()}")
    return new_access_token


def stream_file_stats(cert_file=None):
    # token = os.environ.get('JUPYTERHUB_API_TOKEN', '')
    token = refresh_oidc_token()
    if cert_file and os.path.exists(cert_file):
        session = requests.Session()
        session.cert = cert_file
    url = os.environ.get('DCACHE_URL','') + "/pnfs/cta.cscs.ch/filelists/latest"
    if token:
        headers = {'Authorization': 'Bearer ' + token
                                    }
    else:
        headers = {}

    ca_cert_dir = os.environ.get('CA_CERT_DIR', '')
    params = dict(headers=headers, stream=True)
    
    if ca_cert_dir:
        params['verify'] = ca_cert_dir

    with requests.get(url, **params) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            yield line.decode("utf-8")


def filelist_metrics(lines, last_period_h=24):
    metrics = defaultdict(lambda: defaultdict(int))
    path_prefix = '/pnfs/cta.cscs.ch/'
    path_groups = ['lst', 'cta', 'dteam']
    expected_header = 'isum,ipnfsid,path,isize,ictime,imtime,iatime,icrtime'
    date_format = '%Y-%m-%d %H:%M:%S'
    size_col = 3
    time_col = 5  # imtime
    path_col = 2

    time_threshold = datetime.now() - timedelta(hours=last_period_h)

    csv_header = str.strip(lines.__next__())
    assert csv_header == expected_header

    for line_no, line in enumerate(lines):
        data = line.split(',')
        path = data[path_col].strip()
        folder = 'total'
        if path.startswith(path_prefix):
            _folder = path[len(path_prefix):].split('/')[0]
            if _folder in path_groups:
                folder = _folder

        cur_metrics = metrics[folder]

        data_size = int(data[size_col])
        cur_metrics['data_size'] += data_size
        cur_metrics['file_count'] += 1

        try:
            t = data[time_col].strip().split('.')[0]
            t = datetime.strptime(t, date_format)
        except ValueError as er:
            logger.error(
                f'Error while parsing file list : line { line_no + 1} : {er}')
            continue

        if t >= time_threshold:
            cur_metrics['last_data_size'] += data_size
            cur_metrics['last_file_count'] += 1

    tot_metrics = metrics['total']
    for folder in path_groups:
        for k, v in metrics[folder].items():
            tot_metrics[k] += v

    return metrics


def get_arcinfo_json(metrics=True):
    env = os.environ.copy()
    if 'X509_USER_PROXY' not in env:
        env['X509_USER_PROXY'] = \
            "/certificateservice-data/gitlab_ctao_volodymyr_savchenko__arc.crt"

    result = {}

    arcinfo_output = subprocess.check_output(
        ["arcinfo", "-l"], env=env).strip().decode()
    result["info"] = parse_tabbed_output(arcinfo_output)

    try:
        arcstat = json.loads(
            "{" + subprocess.check_output([
                "bash", "-c", "arcstat -a -J -l | grep -v WARN"
                # "bash", "-c", "kubectl exec -it  deployment/hub
                # -n jh-system -- bash -c
                # 'X509_USER_PROXY=/certificateservice-data/
                # gitlab_ctao_volodymyr_savchenko__arc.crt
                # arcstat -a -J -l' | grep -v WARN"
            ], env=env).strip().decode() + "}"
        )
    except subprocess.CalledProcessError:
        arcstat = {"jobs": "error"}

    result["njobs"] = len(arcstat["jobs"])

    psarc = subprocess.check_output(
        ["bash", "-c", "ps aux | grep arc-h"]).strip().decode().split("\n")

    result["psn"] = len(psarc)

    # append file list metrics
    try:
        # cert_file = env['X509_USER_PROXY']
        #cert_file = \
        #    "/certificateservice-data/gitlab_ctao_volodymyr_savchenko__lst.crt"
        lines = stream_file_stats()
        result.update(filelist_metrics(lines))
        result['file_list_status_code'] = 200
    except requests.HTTPError as http_er:
        result['file_list_status_code'] = http_er.request.status_code
    except Exception as general_error:
        logger.error(general_error)

    # kubectl exec -it  deployment/hub -n jh-system -- bash -c
    # 'X509_USER_PROXY=/certificateservice-data/
    # gitlab_ctao_volodymyr_savchenko__arc.crt arcstat -a -J -l'

    # add arcstat
    # add ps aux
    # certificate number and validity
    # dcache space?

    flat_result = flatten_dict(result)

    if metrics:
        # return prometheus format

        r = []

        for k, v in flat_result.items():
            # if v.endswith("Gb"):

            try:
                v = float(v)
            except ValueError:
                continue

            r.append(f'arcservice_{k}{{label="arc"}} {v}')

        return "\n".join(r)

    else:
        return flatten_dict(result)

    # arcinfo = dict(
    #     free_slots=int(
    #         re.search(r"Free slots: ([0-9]*)",
    #                   arcinfo_output.decode()).group(1)),
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
