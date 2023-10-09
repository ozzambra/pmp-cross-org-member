import boto3
import os
import logging
from crhelper import CfnResource

logger = logging.getLogger(__name__)

helper = CfnResource(
    json_logging=True,
    log_level=os.getenv('LOG_LEVEL', 'INFO').upper(),
    boto_level='CRITICAL',
)


def get_org_root_ou_id():
    logger.debug(f"Getting Org Root OU ID : ")
    client = boto3.client('organizations')
    response = client.list_roots()
    root_ou_id = response['Roots'][0]['Id']
    logger.debug(f"Org Root OU ID : {root_ou_id}")
    return root_ou_id


@helper.update
@helper.create
def create(event, context):
    logger.debug("got create")
    # Get Org Root OU ID
    root_id = get_org_root_ou_id()
    helper.Data.update({"root_id": root_id})


@ helper.delete
def delete(event, context):
    logger.debug("got delete")


def handler(event, context):
    helper(event, context)
