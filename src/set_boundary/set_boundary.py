import boto3
from botocore.exceptions import ClientError
import os
import logging
from crhelper import CfnResource

logger = logging.getLogger(__name__)

helper = CfnResource(
    json_logging=True,
    log_level=os.getenv('LOG_LEVEL', 'INFO').upper(),
    boto_level='CRITICAL',
)

iam = boto3.resource('iam')
iam_client = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')
principal_with_previous_boundary = dynamodb.Table(
    os.environ['PrincipalWithPreviousBoundaryTableName'])
permissions_boundary_arn = os.environ['PermissionsBoundaryArn']

ignore_boundary_users = os.getenv("IgnoreBoundaryForUsers", "").split(",")
ignore_boundary_roles = os.getenv("IgnoreBoundaryForRoles", "").split(",")


def put_user_permissions_boundary():
    principals_with_previous_boundaries = False

    for user in iam.users.all():
        if user.user_name in ignore_boundary_users:
            continue
        try:
            u = iam_client.get_user(UserName=user.user_name)["User"]
            if u.get("PermissionsBoundary") is None or u["PermissionsBoundary"]["PermissionsBoundaryArn"] == permissions_boundary_arn:
                logger.debug(f"Setting boundary to User {u['UserName']}")
                iam_client.put_user_permissions_boundary(
                    UserName=u['UserName'], PermissionsBoundary=permissions_boundary_arn)
            else:
                logger.debug(f"User {user.user_name} has a previous boundary")
                put_error(principal_with_previous_boundary,
                          user.user_name, "user")
                principals_with_previous_boundaries = True
        except ClientError as e:
            logger.error(e)
            raise
    return not principals_with_previous_boundaries


def delete_user_permissions_boundary():
    for user in iam.users.all():
        if user.user_name in ignore_boundary_users:
            continue
        try:
            u = iam_client.get_user(UserName=user.user_name)["User"]
            if u.get("PermissionsBoundary") is not None and u["PermissionsBoundary"]["PermissionsBoundaryArn"] == permissions_boundary_arn:
                logger.debug(f"Deleting boundary from User {u['UserName']}")
                iam_client.delete_user_permissions_boundary(
                    UserName=u['UserName'])
            else:
                logger.debug(f"User {user.user_name} had a different boundary")
        except ClientError as e:
            logger.error(e)
            raise


def put_role_permissions_boundary():
    principals_with_previous_boundaries = False

    for role in iam.roles.all():
        if role.role_name in ignore_boundary_roles:
            continue
        try:
            r = iam_client.get_role(RoleName=role.role_name)["Role"]
            if r.get("PermissionsBoundary") is None or r["PermissionsBoundary"]["PermissionsBoundaryArn"] == permissions_boundary_arn:
                logger.debug(f"Setting boundary to Role {r['RoleName']}")
                iam_client.put_role_permissions_boundary(
                    RoleName=r['RoleName'], PermissionsBoundary=permissions_boundary_arn)
            else:
                logger.debug(f"Role {role.role_name} has a previous boundary")
                put_error(principal_with_previous_boundary,
                          role.role_name, "role")
                principals_with_previous_boundaries = True
        except ClientError as e:
            logger.error(e)
            raise
    return not principals_with_previous_boundaries


def delete_role_permissions_boundary():
    for role in iam.roles.all():
        if role.role_name in ignore_boundary_roles:
            continue
        try:
            r = iam_client.get_role(RoleName=role.role_name)["Role"]
            if r.get("PermissionsBoundary") is not None and r["PermissionsBoundary"]["PermissionsBoundaryArn"] == permissions_boundary_arn:
                logger.debug(f"Deleting boundary from Role {r['RoleName']}")
                iam_client.delete_role_permissions_boundary(
                    RoleName=r['RoleName'])
            else:
                logger.debug(f"Role {role.role_name} had a different boundary")
        except ClientError as e:
            logger.error(e)
            raise


def put_error(table, name, type):
    table.put_item(Item={'name': name, 'type': type})


def put_permission_boundary():
    users_with_previous_boundaries = put_user_permissions_boundary()
    roles_with_previous_boundaries = put_role_permissions_boundary()
    return users_with_previous_boundaries or roles_with_previous_boundaries


def delete_permission_boundary():
    delete_user_permissions_boundary()
    delete_role_permissions_boundary()


@helper.create
def create(event, context):
    logger.info("got create")
    return put_permission_boundary()


@helper.update
def update(event, contect):
    logger.info("got update")
    return put_permission_boundary()


@helper.delete
def delete(event, context):
    logger.info("got delete")
    return delete_permission_boundary()


def handler(event, context):
    helper(event, context)
