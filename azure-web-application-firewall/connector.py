"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations
from .microsoft_api_auth import check, AUTH_BEHALF_OF_USER
from connectors.core.utils import update_connnector_config

logger = get_logger('azure-web-app-firewall')


class AzureFirewall(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            connector_info = {
                    "connector_name": self._info_json.get('name'),
                    "connector_version": self._info_json.get('version')
                    }
            config["connector_info"] = connector_info
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params, connector_info)

    def check_health(self, config):
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        check(config, connector_info)

    def on_update_config(self, old_config, new_config, active):
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}

        if new_config.get('auth_type', '') == AUTH_BEHALF_OF_USER:
            old_auth_code = old_config.get('code')
            new_auth_code = new_config.get('code')
            if old_auth_code != new_auth_code:
                new_config.pop('accessToken', '')
            else:
                new_config['accessToken'] = old_config.get('accessToken')
                new_config['expiresOn'] = old_config.get('expiresOn')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], new_config,
                                     new_config['config_id'])