#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import boto3
import configparser
import os
import json
import sys
import re
import time
import csv
from sty import fg, rs

def get_sso_session(roleName='AWS-Infosec',accountID='012345678910',region_name='eu-west-1'):
    """
    Function retrieve boto3 session and credentials when sso-logged

    Parameters
    ----------
    - roleName (string) : sso_role_name (default AWS-Infosec)
    - sso_account_id = 012345678910
    - region_name (string) : AWS region (default eu-west-1)

    Returns
    -------
    dict : {session:session,credentials:credentials,accessToken:accessToken)
        - session (boto3.Session object)
        - credentials (dict) : 
            {accessKeyId: aws_access_key_id,
             secretAccessKey: aws_secret_access_key,
             sessionToken: aws_session_token}
        - accessToken (str) : accessToken of sso login     
    """
    dir = os.path.expanduser('~/.aws/sso/cache')
    json_files = [pos_json for pos_json in os.listdir(dir) if pos_json.endswith('.json')]
    accessToken = None
    for json_file in json_files :
        path = dir + '/' + json_file
        with open(path) as file :
            data = json.load(file)
            if 'accessToken' in data:
                accessToken = data['accessToken']
    if not accessToken:
        print('No accessToken found, please login before (aws sso login)')
        exit()
    client = boto3.client('sso',region_name=region_name)
    try:
        credentials = client.get_role_credentials(
            roleName=roleName,
            accountId=accountID,
            accessToken=accessToken)
    except:
        print('Invalid credentials, please login (awssso login)')
        return None
    session = boto3.Session(aws_access_key_id=credentials['roleCredentials']['accessKeyId'], aws_secret_access_key=credentials['roleCredentials']['secretAccessKey'], aws_session_token=credentials['roleCredentials']['sessionToken'], region_name=region_name)
    return {'session':session,'credentials':credentials['roleCredentials'],'accessToken':accessToken}

def get_accounts(accessToken,boto3Session=boto3.Session(profile_name='default')):
    """
    Retrieve list of accountsID accessible via aws sso
    - Parameters:
    accessToken (str): SSO acceessToken (placed in json file under .aws/sso/cache directory)
    boto3Session (obj): boto2 session object
    - Response:
      list_account (list): list with accounts ID's
"""
    list_accounts =[]
    client = boto3Session.client('sso')
    response = client.list_accounts(accessToken=accessToken)
    accounts = response['accountList']
    nextToken = response['nextToken']    
    list_accounts += accounts
    while nextToken:
        response = client.list_accounts(accessToken=accessToken,nextToken=nextToken)
        accounts = response['accountList']
        list_accounts += accounts
        if 'nextToken'in response.keys():
            nextToken = response['nextToken']
        else:
            nextToken = None
    print('\n{}***** Total accounts found {} *****{}\n'.format(fg.li_cyan,len(list_accounts),fg.rs))
    return list_accounts

def list_users(boto3Session=boto3.Session(profile_name='default')):
    """
    INPUT: boto3Session with the desired profile
            Ex: bot3Session = boto3.Session(profile_name='Develop_Account')Return dictionary with the users in the account {key:UserName ,value:user_Arn}
    """
    users = boto3Session.client('iam').list_users()['Users']
    dict_users = {}
    for element in users:
        dict_users[element['UserName']] = element['Arn']
    return dict_users


def list_roles(boto3Session=boto3.Session(profile_name='default')):
    """
    INPUT: boto3Session with the desired profile
            Ex: bot3Session = boto3.Session(profile_name='Develop_Account')
    Return dictionary with the users in the account
    {key:RoleName ,value:role_Arn}
    """
    roles = boto3Session.client('iam').list_roles()['Roles']
    dict_roles = {}
    for role in roles:
        dict_roles[role['RoleName']] = role['Arn']
    return dict_roles


def list_services_accessed(arn,
                           session=boto3.Session(profile_name='default')):
    """ Return services accessed by the specified entity (list)
    INPUT: session {boto3 Session object}
           arn {str}

    OUTPUT: list of service names accessed [{str}]
    """
    client = session.client('iam')
    accesses = client.generate_service_last_accessed_details(Arn=arn)
    jobid = accesses['JobId']
    services = client.get_service_last_accessed_details(JobId=str(jobid))
    job_status = services['JobStatus']
    print('Waiting for job completion ..')
    while job_status == 'IN_PROGRESS':
        services = client.get_service_last_accessed_details(JobId=str(jobid))
        job_status = services['JobStatus']
        print('.', sep=' ', end='', flush=True)
        pass
    print('\nJobID {} {} !!\n'.format(jobid,job_status))
    accessed_services = []
    for serv in services['ServicesLastAccessed']:
        if serv['TotalAuthenticatedEntities'] > 0:
            accessed_services.append(serv['ServiceNamespace'])
    return accessed_services


def service_access_granting_policies(aws_service,
                                     arn,
                                     boto3Session=boto3.Session(
                                                    profile_name='default')
                                     ):
    """ Return list  with policies (PolicyName)
        Ej: [{'PolicyName': 'AdministratorAccess',
                            'PolicyType': 'MANAGED',
                             'PolicyArn': 'arn:aws:iam::aws:policy/mypolicy'},
            'PolicyName': 'otherpolicy',
                          'PolicyType': 'MANAGED',
                          'PolicyArn': 'arn:aws:iam::aws:policy/otherpolicy'}
            ]
        INPUT:  ARN identifying the entity
                aws service
    """
    client = boto3Session.client('iam')
    granting_policies = client.list_policies_granting_service_access(
                            Arn=arn, ServiceNamespaces=[str(aws_service)])
    result = []
    for policies in granting_policies['PoliciesGrantingServiceAccess']:
        for policy in policies['Policies']:
            result.append(policy['PolicyName'])
    return result


def list_groups(boto3Session=boto3.Session(profile_name='default')):
    """

    Parameters

    Returns
    List of Dictionaries with all groupnames & groupArn
    Ex:
    {'GroupName': 'Security',
     'Arn':'arn:aws:iam::941308576009:group/Security'}

    """
    client = boto3Session.client('iam')
    groups = client.list_groups()['Groups']
    group_list = []
    for group in groups:
        group_list.append(
            {'GroupName': group['GroupName'], 'Arn': group['Arn']})
    return group_list


def get_policy_detail(PolicyArn,
                      boto3Session=boto3.Session(profile_name='default')):
    """
    Parameters
    Arn of the desired policy
    Returns
    RETURN dictionary {'PolicyName':value,'Statement':[values]}
    Ex:
    {'PolicyName': 'IAMUserChangePassword',
    'Statement': [
        {'Effect': 'Allow', 'Action': ['iam:ChangePassword'],
        'Resource': ['arn:aws:iam::*:user/${aws:username}']},
        {'Effect': 'Allow',
         'Action': ['iam:GetAccountPasswordPolicy'],
         'Resource': '*'
         }
        ]
    }
    """
    policy_details = {}
    client = boto3Session.client('iam')
    policy_name = client.get_policy(PolicyArn=PolicyArn
                                    )['Policy']['PolicyName']
    policy_version = client.get_policy(PolicyArn=PolicyArn
                                       )['Policy']['DefaultVersionId']
    pol_statement = \
        client.get_policy_version(PolicyArn=PolicyArn,
                                  VersionId=policy_version
                                  )['PolicyVersion']['Document']['Statement']
    policy_details['PolicyName'] = policy_name
    policy_details['Statement'] = pol_statement
    return policy_details


def get_group_arn(GroupName,
                  boto3Session=boto3.Session(profile_name='default')):
    """Set docstring here.

    Parameters
    ----------
    GroupName: Name of the group

    Returns
    -------
    Arn of the group (string)
    """
    group_arn = ''
    client = boto3Session.client('iam')
    groups = client.list_groups()['Groups']
    try:
        group = list(filter(lambda g: g['GroupName'] == GroupName, groups))[0]
        return group['Arn']
    except Exception:
        return group_arn


def list_user_groups(username,
                     boto3Session=boto3.Session(profile_name='default')):
    """Set docstring here.

    Parameters
    ----------
    username: UserName

    Returns
    -------
    List of groups (GroupName) which the user belongs to
    Ex: ['Developers', 'Billing']
    """
    client = boto3Session.client('iam')
    groups = []
    try:
        group_list = client.list_groups_for_user(UserName=username)['Groups']
    except Exception:
        return []
    for element in group_list:
        group_name = element['GroupName']
        groups.append(group_name)
    return groups


def list_group_all_policies(GroupName,
                            session=boto3.Session(profile_name='default')):
    """
    Function to retrieve all policies of a named group
    Parameters
    ----------
    GroupName:

    Returns
    -------
    Tuple of lists ([],[])
    (group_inline_pol,group_attached_pol)
    """
    client = session.client('iam')
    group_inline_pol = []
    group_attached_pol = []
    try:
        group_policies = client.list_group_policies(GroupName=GroupName)
        group_inline_pol = group_policies['PolicyNames']
    except Exception:
        raise
    try:
        attached_pol = client.list_attached_group_policies(GroupName=GroupName)
        attached_policies_names = attached_pol['AttachedPolicies']
    except Exception:
        raise
    for policy in attached_policies_names:
        group_attached_pol.append(policy['PolicyName'])
    return (group_inline_pol, group_attached_pol)


def getGroupPolicies(GroupName,
                     session=boto3.Session(profile_name='default')):
    """
    Function to retrieve all policies of a named group
    Parameters
    ----------
    GroupName: The IAM name of group
    session: boto3 session object

    Response
    -------
    Tuple of lists ([],[]):
    (g_inline_pol, group_managed_policies)

    g_inline_pol = [{'PolicyName':'string',
                              'Statement':[
                                            {"Condition",
                                             "Effect":"Allow",
                                              "Action":"*",
                                              "Resource":"*"
                                            }
                                           ]
                              }]
    group_managed_policies = [{'PolicyName': 'string',
                               'Statement': [
                                             {'Effect': 'Allow',
                                              'Action': '*',
                                              'Resource': '*'
                                              }
                                              ]
                                            ]

    """
    client = session.client('iam')
    paginator = client.get_paginator('get_account_authorization_details')
    page = paginator.paginate(Filter=['Group'])
    g_inline_pol = []
    g_attach_pol = []
    for element in page:
        for group in element['GroupDetailList']:
            if group['GroupName'] == GroupName:
                if group['GroupPolicyList']:
                    for policy in group['GroupPolicyList']:
                        policyname = policy['PolicyName']
                        policystatement = policy['PolicyDocument']['Statement']
                        g_inline_pol.append({'PolicyName': policyname,
                                             'Statement': policystatement})
                if group['AttachedManagedPolicies']:
                    for policy in group['AttachedManagedPolicies']:
                            policyarn = policy['PolicyArn']
                            attach_policy = get_policy_detail(policyarn, session)
                            policystatement = attach_policy['Statement']
                            g_attach_pol.append({'PolicyName': policy['PolicyName'],
                                             'Statement': policystatement})
    return (g_inline_pol, g_attach_pol)


def getUserPolicies(UserName, boto3Session):
    """
    Function to retrieve all policies of a named user
    Parameters
    ----------
    GroupName: The IAM name of user
    boto3Session: boto3 session object

    Response
    -------
    Tuple of lists ([],[]) -->    (u_inline_pol, user_managed_policies)

    u_inline_pol = [{'PolicyName':'string',
                             'Statement':[
                                         {"Condition",
                                          "Effect":"Allow",
                                          "Action":"*",
                                          "Resource":"*"
                                          }
                                          ]
                            ]
    user_managed_policies = [{'PolicyName': 'string',
                              'Statement': [
                                            {'Effect': 'Allow',
                                             'Action': '*',
                                             'Resource': '*'
                                            }
                                            ]
                            ]

    """
    client = boto3Session.client('iam')
    paginator = client.get_paginator('get_account_authorization_details')
    page = paginator.paginate(Filter=['User'])
    u_inline_pol = []
    u_attach_pol = []
    for element in page:
        for user in element['UserDetailList']:
            if user['UserName'] == UserName:
                if 'UserPolicyList' in user.keys():
                    for policy in user['UserPolicyList']:
                        policyname = policy['PolicyName']
                        policystatement = policy['PolicyDocument']['Statement']
                        u_inline_pol.append({'PolicyName': policyname,
                                             'Statement': policystatement})
                if 'AttachedManagedPolicies' in user.keys():
                    for policy in user['AttachedManagedPolicies']:
                        policyarn = policy['PolicyArn']
                        attach_policy = get_policy_detail(policyarn, boto3Session)
                        policystatement = attach_policy['Statement']
                        u_attach_pol.append({'PolicyName': policy['PolicyName'],
                                         'Statement': policystatement})
    return (u_inline_pol, u_attach_pol)

def getRolePolicies(RoleName, boto3Session):
    """
    Function to retrieve all policies of a named role
    Parameters
    ----------
    GroupName: The IAM name of role
    boto3Session: boto3 session object

    Response
    -------
    Tuple of lists ([],[]) -->    (u_inline_pol, user_managed_policies)

    u_inline_pol = [{'PolicyName':'string',
                             'Statement':[
                                         {"Condition",
                                          "Effect":"Allow",
                                          "Action":"*",
                                          "Resource":"*"
                                          }
                                          ]
                            ]
    user_managed_policies = [{'PolicyName': 'string',
                              'Statement': [
                                            {'Effect': 'Allow',
                                             'Action': '*',
                                             'Resource': '*'
                                            }
                                            ]
                            ]

    """
    client = boto3Session.client('iam')
    paginator = client.get_paginator('get_account_authorization_details')
    page = paginator.paginate(Filter=['Role'])
    u_inline_pol = []
    u_attach_pol = []
    for element in page:
        for role in element['RoleDetailList']:
            if role['RoleName'] == RoleName:
                if 'RolePolicyList' in role.keys():
                    for policy in role['RolePolicyList']:
                        policyname = policy['PolicyName']
                        policystatement = policy['PolicyDocument']['Statement']
                        u_inline_pol.append({'PolicyName': policyname,
                                             'Statement': policystatement})
                if 'AttachedManagedPolicies' in role.keys():
                    for policy in role['AttachedManagedPolicies']:
                        policyarn = policy['PolicyArn']
                        attach_policy = get_policy_detail(policyarn, boto3Session)
                        policystatement = attach_policy['Statement']
                        u_attach_pol.append({'PolicyName': policy['PolicyName'],
                                         'Statement': policystatement})
    return (u_inline_pol, u_attach_pol)

def get_managed_policy_arn(PolicyName, scope='All',
                           boto3Session=boto3.Session(profile_name='default')):
    """
    This function return the Arn of the requested policy

    Parameters
    ----------
    PolicyName:
    scope='All':

    Returns
    -------
    Arn {string}
    """
    client = boto3Session.client('iam')
    paginator = client.get_paginator('list_policies')
    response_iterator = paginator.paginate(Scope=scope)
    # l=response_iterator.search('Policies[].[PolicyName,Arn]')
    for element in response_iterator.search('Policies[].[PolicyName,Arn]'):
        if element[0] == PolicyName:
            return element[1]
    return


def entity_accesses(arn,
                    boto3Session=boto3.Session(profile_name='default')):
    """ Return dictionary containing the services accessed by the user
    and the list of granting policies
    {'ServiceName':[list of granting policies to ServiceName]}
    INPUT: -  ARN describing the user
    """
    aws_services_accessed = {}
    access_list = list_services_accessed(arn, boto3Session)
    if not access_list:
        return []
    for aws_service in access_list:
        granting_policies = service_access_granting_policies(aws_service,
                                                             arn,
                                                             boto3Session)
        aws_services_accessed[aws_service] = granting_policies
    return aws_services_accessed


def findAssumeRole(UserName,
                   boto3Session=boto3.Session(profile_name='default')):
    """
    Find AssumeRole policy among all user policies
    Parameters:
        UserName: IAM user name 'str'
        boto3Session: boto3 session object
    Response:
        User policy that allow AssumeRole -dict-
        {'PolicyName': 'str', 'PolcyDocument': 'dict'}
    """
    user_assume_role_policies = []
    # Getting user inline policies
    user_policies = getUserPolicies(UserName, boto3Session)
    if user_policies[0]:
        for inline_policy in user_policies[0]:
            statements = inline_policy['Statement']
            for statement in statements:
                if statement['Action'] == "sts:AssumeRole":
                    user_assume_role_policies.append(inline_policy)
    if user_policies[1]:
        for attached_policy in user_policies[1]:
            statements = attached_policy['Statement']
            for statement in statements:
                if statement['Action'] == "sts:AssumeRole":
                    user_assume_role_policies.append(attached_policy)
    # Getting user group policies
    group_assume_role_policies = []
    groups = list_user_groups(UserName, boto3Session)
    for group in groups:
        group_policies = getGroupPolicies(group, boto3Session)
        if group_policies[0]:
            for inline_policy in group_policies[0]:
                statements = inline_policy['Statement']
                for statement in statements:
                    if statement['Action'] == "sts:AssumeRole":
                        group_assume_role_policies.append(inline_policy)
        if group_policies[1]:
            for attached_policy in group_policies[1]:
                statements = attached_policy['Statement']
                for statement in statements:
                    if statement['Action'] == "sts:AssumeRole":
                        group_assume_role_policies.append(inline_policy)
    return (user_assume_role_policies, group_assume_role_policies)

def parse_document(document, identity):
    """
    Extract all permission from a policy document
    Parameters:
        document (dict): Policy document, {'PolicyName':'policy name','Statement': [{...}]}
        identity (dict): Identity dictionary, {'IdentityName': 'rol or user name', 'Permissions': {'Allow': {(empty)}, 'Deny': {(empty)}}}
    Response:
        Identity (dict): Dictionary containing Identity Name a its permissions
        
        {'IdentityName': 'rol or user name', 'Permissions': {'Allow': {.....}, 'Deny': {....}}}
    Example:
    identity = {'IdentityName': 'myrolename', 'Permissions': {'Allow': {}, 'Deny': {}}}
    myidentity = parse_document(document, identity)
    """      
    if type(document['Statement']) is dict:
        document['Statement'] = [document['Statement']]
    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and type(statement['Action']) is list: # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in identity['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Allow'][action] += statement['Resource']
                        else:
                            identity['Permissions']['Allow'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Allow'][action] = statement['Resource']
                        else:
                            identity['Permissions']['Allow'][action] = [statement['Resource']]
                    identity['Permissions']['Allow'][action] = list(set(identity['Permissions']['Allow'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in identity['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Allow'][statement['Action']] += statement['Resource']
                    else:
                        identity['Permissions']['Allow'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Allow'][statement['Action']] = statement['Resource']
                    else:
                        identity['Permissions']['Allow'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                identity['Permissions']['Allow'][statement['Action']] = list(set(identity['Permissions']['Allow'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in identity['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Deny'][not_action] += statement['Resource']
                        else:
                            identity['Permissions']['Deny'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Deny'][not_action] = statement['Resource']
                        else:
                            identity['Permissions']['Deny'][not_action] = [statement['Resource']]
                    identity['Permissions']['Deny'][not_action] = list(set(identity['Permissions']['Deny'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in identity['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Deny'][statement['NotAction']] += statement['Resource']
                    else:
                        identity['Permissions']['Deny'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Deny'][statement['NotAction']] = statement['Resource']
                    else:
                        identity['Permissions']['Deny'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                identity['Permissions']['Deny'][statement['NotAction']] = list(set(identity['Permissions']['Deny'][statement['NotAction']])) # Remove duplicate resources
        if statement['Effect'] == 'Deny':
            if 'Action' in statement and type(statement['Action']) is list:
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in identity['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Deny'][action] += statement['Resource']
                        else:
                            identity['Permissions']['Deny'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Deny'][action] = statement['Resource']
                        else:
                            identity['Permissions']['Deny'][action] = [statement['Resource']]
                    identity['Permissions']['Deny'][action] = list(set(identity['Permissions']['Deny'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in identity['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Deny'][statement['Action']] += statement['Resource']
                    else:
                        identity['Permissions']['Deny'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Deny'][statement['Action']] = statement['Resource']
                    else:
                        identity['Permissions']['Deny'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                identity['Permissions']['Deny'][statement['Action']] = list(set(identity['Permissions']['Deny'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in identity['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Allow'][not_action] += statement['Resource']
                        else:
                            identity['Permissions']['Allow'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            identity['Permissions']['Allow'][not_action] = statement['Resource']
                        else:
                            identity['Permissions']['Allow'][not_action] = [statement['Resource']]
                    identity['Permissions']['Allow'][not_action] = list(set(identity['Permissions']['Allow'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in identity['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Allow'][statement['NotAction']] += statement['Resource']
                    else:
                        identity['Permissions']['Allow'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        identity['Permissions']['Allow'][statement['NotAction']] = statement['Resource']
                    else:
                        identity['Permissions']['Allow'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                identity['Permissions']['Allow'][statement['NotAction']] = list(set(identity['Permissions']['Allow'][statement['NotAction']])) # Remove duplicate resources
    return identity

def scan_privileges(identity,output_file):
    """
    Scan for privilege escalation
    Parameters:
       - identity (dict):  Identity dictionary  
        {'IdentityName': 'rol or user name',
        'Permissions': {'Allow': {...}, 'Deny': {...}}}
        - output_file (str): accountID to generate name of output_file    
    Response:
        - Writes results in csv file output_file
        - identity (dict):  Identity dictionary
        {'IdentityName': 'rol or user name', 
        'Permissions': {'Allow': {...}, 'Deny': {...}}, 
        'CheckedMethods' : {'Potential': [(list)],Confirmed': [(list)]}
        }

    """  
    all_perms = [
        'iam:AddUserToGroup',
        'iam:AttachGroupPolicy',
        'iam:AttachRolePolicy',
        'iam:AttachUserPolicy',
        'iam:CreateAccessKey',
        'iam:CreatePolicyVersion',
        'iam:CreateLoginProfile',
        'iam:PassRole',
        'iam:PutGroupPolicy',
        'iam:PutRolePolicy',
        'iam:PutUserPolicy',
        'iam:SetDefaultPolicyVersion',
        'iam:UpdateAssumeRolePolicy',
        'iam:UpdateLoginProfile',
        'sts:AssumeRole',
        'ec2:RunInstances',
        'lambda:CreateEventSourceMapping',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'lambda:UpdateFunctionCode',
        'dynamodb:CreateTable',
        'dynamodb:PutItem',
        'glue:CreateDevEndpoint',
        'glue:UpdateDevEndpoint',
        'cloudformation:CreateStack',
        'datapipeline:CreatePipeline'
    ]

    escalation_methods = {
        'CreateNewPolicyVersion': {
            'iam:CreatePolicyVersion': True
        },
        'SetExistingDefaultPolicyVersion': {
            'iam:SetDefaultPolicyVersion': True
        },
        'CreateEC2WithExistingIP': {
            'iam:PassRole': True,
            'ec2:RunInstances': True
        },
        'CreateAccessKey': {
            'iam:CreateAccessKey': True
        },
        'CreateLoginProfile': {
            'iam:CreateLoginProfile': True
        },
        'UpdateLoginProfile': {
            'iam:UpdateLoginProfile': True
        },
        'AttachUserPolicy': {
            'iam:AttachUserPolicy': True
        },
        'AttachGroupPolicy': {
            'iam:AttachGroupPolicy': True
        },
        'AttachRolePolicy': {
            'iam:AttachRolePolicy': True,
            'sts:AssumeRole': True
        },
        'PutUserPolicy': {
            'iam:PutUserPolicy': True
        },
        'PutGroupPolicy': {
            'iam:PutGroupPolicy': True
        },
        'PutRolePolicy': {
            'iam:PutRolePolicy': True,
            'sts:AssumeRole': True
        },
        'AddUserToGroup': {
            'iam:AddUserToGroup': True
        },
        'UpdateRolePolicyToAssumeIt': {
            'iam:UpdateAssumeRolePolicy': True,
            'sts:AssumeRole': True
        },
        'PassExistingRoleToNewLambdaThenInvoke': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True,
            'lambda:InvokeFunction': True
        },
        'PassExistingRoleToNewLambdaThenTriggerWithNewDynamo': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True,
            'lambda:CreateEventSourceMapping': True,
            'dynamodb:CreateTable': True,
            'dynamodb:PutItem': True
        },
        'PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo': {
            'iam:PassRole': True,
            'lambda:CreateFunction': True,
            'lambda:CreateEventSourceMapping': True
        },
        'PassExistingRoleToNewGlueDevEndpoint': {
            'iam:PassRole': True,
            'glue:CreateDevEndpoint': True
        },
        'UpdateExistingGlueDevEndpoint': {
            'glue:UpdateDevEndpoint': True
        },
        'PassExistingRoleToCloudFormation': {
            'iam:PassRole': True,
            'cloudformation:CreateStack': True
        },
        'PassExistingRoleToNewDataPipeline': {
            'iam:PassRole': True,
            'datapipeline:CreatePipeline': True
        },
        'EditExistingLambdaFunctionWithRole': {
            'lambda:UpdateFunctionCode': True
        }
    }
    # Preprare output file
    headers = ['CreateNewPolicyVersion','SetExistingDefaultPolicyVersion','CreateEC2WithExistingIP','CreateAccessKey','CreateLoginProfile','UpdateLoginProfile','AttachUserPolicy','AttachGroupPolicy','AttachRolePolicy','PutUserPolicy','PutGroupPolicy','PutRolePolicy','AddUserToGroup','UpdateRolePolicyToAssumeIt','PassExistingRoleToNewLambdaThenInvoke','PassExistingRoleToNewLambdaThenTriggerWithNewDynamo','PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo','PassExistingRoleToNewGlueDevEndpoint','UpdateExistingGlueDevEndpoint','PassExistingRoleToCloudFormation','PassExistingRoleToNewDataPipeline','EditExistingLambdaFunctionWithRole']
    if not os.path.isfile(output_file):
        print('File not exists, creating')
        #init file with headers
        with open(output_file, 'a', newline='') as  csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=['Identity']  +headers)
            #print(['Identity'] +headers)
                writer.writeheader()
    #print(fg. +'Identity: {}'.format(identity['IdentityName']))
    #print(fg.rs)
    checked_perms = {'Allow': {}, 'Deny': {}}
    # Preliminary check to see if these permissions have already been enumerated in this session
    admin = False
    if 'Permissions' in identity and 'Allow' in identity['Permissions']:
        # Are they an admin already?
        if '*' in identity['Permissions']['Allow'] and identity['Permissions']['Allow']['*'] == ['*']:
            identity['CheckedMethods'] = {'admin': {}, 'Confirmed':{},'Potential': {}}
            print(fg.red+'  Already an admin!\n')
            print(fg.rs)
            admin = True
        else:        
            for perm in all_perms:
                for effect in ['Allow', 'Deny']:
                    if perm in identity['Permissions'][effect]:
                        checked_perms[effect][perm] = identity['Permissions'][effect][perm]
                    else:
                        for identity_perm in identity['Permissions'][effect].keys():
                            if '*' in identity_perm:
                                pattern = re.compile(identity_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = identity['Permissions'][effect][identity_perm]
    checked_methods = {
        'Potential': [],
        'Confirmed': []
    }
    # Ditch each escalation method that has been confirmed not to be possible
    for method in escalation_methods:
        potential = True
        confirmed = True
        for perm in escalation_methods[method]:
            if perm not in checked_perms['Allow']: # If this permission isn't Allowed, then this method won't work
                potential = confirmed = False
                break
            elif perm in checked_perms['Deny'] and perm in checked_perms['Allow']: # Permission is both Denied and Allowed, leave as potential, not confirmed
                confirmed = False
            elif perm in checked_perms['Allow'] and perm not in checked_perms['Deny']: # It is Allowed and not Denied
                if not checked_perms['Allow'][perm] == ['*']:
                    confirmed = False
        if confirmed is True:
            print(fg.red+'  CONFIRMED escalation method: {}\n'.format(method))
            print(fg.rs)
            checked_methods['Confirmed'].append(method)
        elif potential is True:
            print(fg.yellow+'  POTENTIAL escalation method: {}\n'.format(method))
            print(fg.rs)
            checked_methods['Potential'].append(method)

    identity['CheckedMethods'] = checked_methods
    if checked_methods['Potential'] == [] and checked_methods['Confirmed'] == [] and not admin:
        print(fg.green+'  No methods possible.\n'+fg.rs)

    # Prepare dictionary for csv building
    identity_methods_dict = {'Identity':identity['IdentityName']}
    for method in headers:
        identity_methods_dict[method] = ''
        if admin:
            identity_methods_dict[method] = '**admin**'
        else:
            if method in checked_methods['Potential']:
                identity_methods_dict[method] = 'Potential'
            if method in checked_methods['Confirmed']:
                identity_methods_dict[method] = 'Confirmed'
    with open(output_file, 'a', newline='') as  csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=['Identity']  +headers)
        #print(['Identity'] +headers)
        writer.writerow(identity_methods_dict)
   
    #print('Privilege escalation check for {} completed.\n Results written in ./{}\n\n'.format(identity['IdentityName'],output_file))
    return identity

if __name__ == "__main__":

    default_accountID = '012345678910'
    sso_session = get_sso_session(accountID=default_accountID)
    accessToken = sso_session['accessToken']
    boto3Session = sso_session['session']
    account_list = get_accounts(accessToken,boto3Session)
    for account in account_list:
        accountId = account['accountId']
        print(fg.li_blue+'** Analyzing account: {}'.format(accountId))
        boto3Session = get_sso_session(accountID=accountId)['session']
        users = list(list_users(boto3Session).keys())
        roles = list(list_roles(boto3Session).keys())
        print('{}  - Users in {} account: {}{}'.format(fg.li_green,accountId,fg.rs,users))
        print('{}  - Roles in {} account: {}{}'.format(fg.li_green,accountId,fg.rs,roles))       
        for username in users:
            identity = {'IdentityName': username, 'Permissions': {'Allow': {}, 'Deny': {}}}
            policies = getUserPolicies(username,boto3Session)
            for policy_type in policies:
                if policy_type:
                    for policy in policy_type:
                        r = parse_document(policy,identity)
            print(fg.li_cyan +'--> Analysing Identity: {} <--'.format(r['IdentityName']))
            print(fg.rs)
            scan_privileges(r,'scan_of_account_'+accountId+'_users.csv')
            print('   * Privilege escalation check for {} completed.\n   Results written in: --> ./{}\n\n'.format(identity['IdentityName'],'scan_of_account_'+accountId+'_users.csv'))

        for rolename in roles:
            identity = {'IdentityName': rolename, 'Permissions': {'Allow': {}, 'Deny': {}}}
            policies = getRolePolicies(rolename,boto3Session)
            for policy_type in policies:
                if policy_type:
                    for policy in policy_type:
                        r = parse_document(policy,identity)
            print(fg.li_cyan+'--> Analysing Identity: {} <--'.format(r['IdentityName']))
            print(fg.rs)
            result = scan_privileges(r,'scan_of_account_'+accountId+'_roles.csv')
            print('   * Privilege escalation check for {} completed.\n     Results written in: --> ./{}\n\n'.format(identity['IdentityName'],'scan_of_account_'+accountId+'_roles.csv'))
            
