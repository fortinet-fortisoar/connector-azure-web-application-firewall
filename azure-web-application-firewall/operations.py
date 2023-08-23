""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
import requests
from connectors.core.connector import get_logger, ConnectorError
from .microsoft_api_auth import MicrosoftAuth

logger = get_logger('azure-web-application-firewall')


class AzureWebAppFirewall(object):
    def __init__(self, config):
        self.server_url = config.get('resource').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.subscription_id = config.get('subscription_id')
        self.resource_group_name = config.get('resource_group_name')
        self.api_version = config.get('api_version')
        self.verify_ssl = config.get('verify_ssl')
        self.ms_auth = MicrosoftAuth(config)
        self.connector_info = config.pop('connector_info', '')
        self.token = self.ms_auth.validate_token(config, self.connector_info)

    def make_rest_call(self, endpoint, params=None, json=None, payload=None, method='GET'):
        headers = {'Authorization': self.token, 'Content-Type': 'application/json'}
        service_url = self.server_url + endpoint
        logger.debug('Request URL {0}'.format(service_url))
        try:
            response = requests.request(method, service_url, data=payload, headers=headers, json=json, params=params,
                                        verify=self.verify_ssl)

            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")

            if response.ok:
                content_type = response.headers.get('Content-Type')
                if response.text != "" and 'application/json' in content_type:
                    return response.json()
                elif response.status_code == 204 and response.reason == 'No Content':
                    return {"message": "Not Found"}
                elif (response.status_code == 200 and response.reason == 'OK') or (
                        response.status_code == 202 and response.reason == 'Accepted'):
                    return {"message": "Successful"}
                else:
                    return response.content
            else:
                if response.text != "":
                    err_resp = response.json()
                    if "error" in err_resp:
                        error_msg = "{0}: {1}".format(err_resp.get('error').get('code'),
                                                      err_resp.get('error').get('message'))
                        raise ConnectorError(error_msg)
                    else:
                        raise ConnectorError(err_resp)
                else:
                    error_msg = '{0}: {1}'.format(response.status_code, response.reason)
                    raise ConnectorError(error_msg)
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def create_or_update_policy(config: dict, params: dict) -> dict:
    try:
        params = _build_payload(params)
        endpoint = f"/subscriptions/{config.get('subscription_id')}/resourceGroups/{config.get('resource_group_name')}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{params.get('policy_name')}?api-version={config.get('api_version')}"
        method = "PUT"
        prop_dict = {"properties": {}}

        for p in ['managedRules', 'customRules', 'policySettings']:
            if params.get(p) is not None:
                prop_dict.get("properties").update(params.pop(p))

        params.update(prop_dict)
        AZ = AzureWebAppFirewall(config=config)
        response = AZ.make_rest_call(endpoint=endpoint, method=method, payload=params)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Create or Update Policies {err}")
        raise ConnectorError(err)


def delete_policy(config: dict, params: dict) -> dict:
    try:
        endpoint = f"/subscriptions/{config.get('subscription_id')}/resourceGroups/{config.get('resource_group_name')}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{params.get('policy_name')}?api-version={config.get('api_version')}"
        method = "DELETE"

        AZ = AzureWebAppFirewall(config=config)
        response = AZ.make_rest_call(endpoint=endpoint, method=method)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Delete Policy {err}")
        raise ConnectorError(err)


def get_policy(config: dict, params: dict) -> dict:
    try:
        endpoint = f"/subscriptions/{config.get('subscription_id')}/resourceGroups/{config.get('resource_group_name')}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{params.get('policy_name')}?api-version={config.get('api_version')}"
        method = "GET"

        AZ = AzureWebAppFirewall(config=config)
        response = AZ.make_rest_call(endpoint=endpoint, method=method)
        return response
    except Exception as err:
        logger.error(f"Error Occurred in Get Policy {err}")
        raise ConnectorError(err)


def list_policies(config: dict, params: dict) -> dict:
    try:
        if params.get("option") == "Within a Resource Group":
            endpoint = f"/subscriptions/{config.get('subscription_id')}/resourceGroups/{config.get('resource_group_name')}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies?api-version={config.get('api_version')}"
            method = "GET"
            AZ = AzureWebAppFirewall(config=config)
            response = AZ.make_rest_call(endpoint=endpoint, method=method)
            return response
        else:
            endpoint = f"/subscriptions/{config.get('subscription_id')}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies?api-version={config.get('api-version')}"
            method = "GET"
            AZ = AzureWebAppFirewall(config=config)
            response = AZ.make_rest_call(endpoint=endpoint, method=method)
            return response
    except Exception as err:
        logger.error(f"Error Occurred in List Policies {err}")
        raise ConnectorError(err)


def _build_payload(params):
    return {key: val for key, val in params.items() if val is not None and val != ''}


operations = {
    "create_or_update_policy": create_or_update_policy,
    "delete_policy": delete_policy,
    "get_policy": get_policy,
    "list_policies": list_policies,
}
