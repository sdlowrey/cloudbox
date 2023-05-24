"""
Provides an AwsIdc class for assuming roles in AWS accounts under AWS Identity 
Center (IdC, formerly known as SSO).
"""
import os
import webbrowser

from time import sleep

import boto3


class AwsIdc:
    """Provides AWS SSO/IdC authenticaton using OIDC.
    """
    def __init__(self, start_url, region, timeout):
        self._region = region
        self._timeout = timeout
        self._start_url = start_url
        self._access_token = self._get_oidc_token()
        self._sso_client = boto3.client('sso', region_name=self._region)

    def _get_oidc_token(self):
        """Register client to SSO with OIDC and return API access token.

        A browser is opened with the authorization verification request. User must
        respond within the timeout period or the create_token call will fail.
        """
        oidc = boto3.client('sso-oidc', region_name=self._region)
        reg_response = oidc.register_client(clientName='sso', clientType='public')

        auth_response = oidc.start_device_authorization(
            clientId=reg_response['clientId'],
            clientSecret=reg_response['clientSecret'],
            startUrl=self._start_url
        )

        # send the verification URL to a browser for user confirmation
        webbrowser.open(auth_response['verificationUriComplete'])
        sleep(self._timeout)

        # get SSO access token; caller must handle execptions
        create_token = oidc.create_token(
            clientId=reg_response['clientId'],
            clientSecret=reg_response['clientSecret'],
            grantType='urn:ietf:params:oauth:grant-type:device_code',
            deviceCode=auth_response['deviceCode'],
            code=auth_response['userCode'],
            redirectUri=auth_response['verificationUriComplete']
        )
        return create_token['accessToken']

    def get_accounts(self, account_filter: str = None):
        """Return a list of all accounts from SSO. Requires OIDC access token.

        The optional account_filter string is a comma-separated list of
        account IDs.
        """
        accounts = []
        paginator = self._sso_client.get_paginator('list_accounts')
        page_iter = paginator.paginate(accessToken=self._access_token)
        for page in page_iter:
            accounts.extend(page['accountList'])

        if account_filter is None:
            return accounts

        filter_list = account_filter.split(',')
        filtered_accounts = []
        for account in accounts:
            if account['accountId'] in filter_list:
                filtered_accounts.append(account)
        return filtered_accounts

    def get_session(self, account_id: str, role_name: str):
        """Get STS role credentials for an account and return an API session.
        """
        credentials = self._sso_client.get_role_credentials(
            roleName=role_name,
            accountId=account_id,
            accessToken=self._access_token
        )
        role_creds = credentials['roleCredentials']
        kwargs = {
            'aws_access_key_id': role_creds['accessKeyId'],
            'aws_secret_access_key': role_creds['secretAccessKey'],
            'aws_session_token': role_creds['sessionToken']
        }
        return boto3.session.Session(**kwargs)
