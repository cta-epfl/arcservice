from typing import Any
import pytest
import os
from arcservice.app import stream_file_stats, filelist_metrics


def test_filestat(certificates: Any):
    os.environ['DCACHE_URL'] = 'https://dcache-dev.ctaodc.ch:2880'
    os.environ['DCACHE_CLIENT_ID'] = 'dcache-dev'
    os.environ['CA_CERT'] = certificates
    os.environ['DCACHE_REFRESH_TOKEN'] = "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSl" \
        "dUIiwia2lkIiA6ICJhOWFiNTBhOS1hMGFjLTRkZDAtYWVhMS00YzZlOWUzZWE5YWEif" \
        "Q.eyJpYXQiOjE3NDMwODM3MzYsImp0aSI6IjMzMzlkZjY3LWRjOGItNGRlNS05YjM0L" \
        "TA2MThkYjA5ODYwZiIsImlzcyI6Imh0dHBzOi8va2V5Y2xvYWsuY3RhLmNzY3MuY2gv" \
        "cmVhbG1zL21hc3RlciIsImF1ZCI6Imh0dHBzOi8va2V5Y2xvYWsuY3RhLmNzY3MuY2g" \
        "vcmVhbG1zL21hc3RlciIsInN1YiI6IjJiZTlkYjc1LWE3ZTEtNGI3Yi1iN2JjLTYxYT" \
        "AzMmM3NzQ4MCIsInR5cCI6Ik9mZmxpbmUiLCJhenAiOiJkY2FjaGUtZGV2Iiwic2Vzc" \
        "2lvbl9zdGF0ZSI6IjFiNjJmZjIwLWUzYzgtNGJhOS1iZTA5LTgxYjU1MGFiZjNjMSIs" \
        "InNjb3BlIjoib3BlbmlkIG9mZmxpbmVfYWNjZXNzIHByb2ZpbGUgZW1haWwgY3RhbyI" \
        "sInNpZCI6IjFiNjJmZjIwLWUzYzgtNGJhOS1iZTA5LTgxYjU1MGFiZjNjMSJ9.gO9iY" \
        "AoQzKLJHlGrwaxxd5PrXW8y1npXT5ywM7NayaqtPJ9ftrC4LrBD0d4BVVfzDEv3MIB5" \
        "gyXBCUu0gSCXLg"

    os.environ['DCACHE_CLIENT_SECRET'] = 'sedN6x92foO3AQfYw9HKfeqYZBm7kMQx'
    lines = stream_file_stats()
    print(filelist_metrics(lines))
