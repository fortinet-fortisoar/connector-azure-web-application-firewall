""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from .microsoft_api_auth import MicrosoftAuth
from operations import AzureWebAppFirewall
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('azure-web-application-firewall')

def _check_health(config: dict) -> bool:
    try:
        endpoint = f"/subscriptions/{config.get('subscription_id')}/resourceGroups/{config.get('resource_group_name')}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies?api-version={config.get('api_version')}"
        method = "GET"
        AZ = AzureWebAppFirewall(config=config)
        AZ.make_rest_call(endpoint=endpoint, method=method)
        return True
    except Exception as e:
        raise ConnectorError(f"Exception in Check health {e}")