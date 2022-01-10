""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
import re
import os
from datetime import datetime
from bs4 import BeautifulSoup
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('botvrij-misp-osint-feed')


def _get_page_content(config):
    try:
        server_url = config.get('server_url')
        response = requests.get(server_url)
        if not response.ok:
            raise ConnectorError('Unable to access the feed URL. Check connectivity and retry. Error status: ' + response.status_code)
        soup = BeautifulSoup(response.content, 'html.parser')
        if not 'feed-osint' in soup.title.string:
            raise ConnectorError('Invalid URL for OSINT Feed')
        return soup
    except ConnectorError as ce:
        raise ce
    except Exception as e:
        logger.exception('Failed parsing URL content')
        raise ConnectorError('Failed parsing URL content with error: ' + str(e))

def get_collections(config, params, **kwargs):
    last_pull_time = params.get('modified_after')
    collections_refreshed = []
    soup = _get_page_content(config)
    for line in soup.get_text().split('\n'):
        line = re.sub(r'\s\s+', '\t', line)
        parsed = line.split('\t')
        if (len(parsed) > 2):
            collection_json = parsed[0].strip()
            if collection_json != 'hashes.csv' and collection_json != 'manifest.json':
                # honor time filter if passed
                if last_pull_time and type(last_pull_time) == int:
                    time_modified = parsed[1]
                    epoch_timestamp = datetime.strptime(time_modified, '%d-%b-%Y %H:%M').timestamp()
                    if epoch_timestamp < last_pull_time:
                        continue
                collections_refreshed.append(collection_json)
    return collections_refreshed
        

def get_events(config, params, **kwargs):
    server_url = config.get('server_url').rstrip('/') + '/'
    collection_id = params.get('collectionID')
    if not collection_id:
        raise ConnectorError('A valid collection id of the format <uuid>.json is required')
    collection_url = server_url + collection_id

    modified_after = params.get("modified_after")
    # create_pb_id = params.get("create_pb_id")
    
    event_response = requests.get(collection_url)
    if event_response.ok:
        event_json = event_response.json()
        event_modify_time = int(event_json["Event"]["publish_timestamp"])
        if modified_after and type(modified_after) == int:
            if event_modify_time < modified_after:
                return {}
        return event_json
    return {}
    

def check_health(config):
    _get_page_content(config)


operations = {
    'get_objects_by_collection_id': get_events,
    'get_collections': get_collections,
    'check_health': check_health,
}
