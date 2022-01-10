""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
""" 
from connectors.core.connector import Connector, get_logger, ConnectorError

from .operations import operations

logger = get_logger('botvrij-misp-osint-feed')


class MISPFeedBotvrij(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('In execute() Operation: {}'.format(operation))
            operation = operations.get(operation)
            return operation(config, params, **kwargs)
        except Exception as err:
            logger.error('An exception occurred {}'.format(err))
            raise ConnectorError('{}'.format(err))

    def check_health(self, config):
        try:
            return operations.get('check_health')(config)
        except Exception as e:
            logger.exception("An exception occurred {}".format(e))
            raise ConnectorError(e)
