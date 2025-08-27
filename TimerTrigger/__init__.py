import logging,os
import azure.functions as func

from azure.identity import DefaultAzureCredential
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.containerapp import ContainerAppsAPIClient
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.logic import LogicManagementClient

# === 설정 ===
SECURITY_SUBSCRIPTION_ID = os.environ['']
WORKLOAD_SUBSCRIPTIONS = [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
]

def get_cmk_uamis(msi_client):
    all_uamis = msi_client.user_assigned_identities.list_by_subscription()
    return [u for u in all_uamis if u.name.lower().endswith("-cmk")]

def is_uami_used(uami_id, identities):
    return identities and uami_id.lower() in [k.lower() for k in identities.keys()]

def find_resources_using_uami(credential, subscriptions, cmk_uamis):
    results = []

    for sub_id in subscriptions:
        uami_ids = [u.id.lower() for u in cmk_uamis]

        # Clients
        compute_client = ComputeManagementClient(credential, sub_id)
        web_client = WebSiteManagementClient(credential, sub_id)
        container_client = ContainerAppsAPIClient(credential, sub_id)
        adf_client = DataFactoryManagementClient(credential, sub_id)
        logic_client = LogicManagementClient(credential, sub_id)

        # VM
        for vm in compute_client.virtual_machines.list_all():
            identities = vm.identity.user_assigned_identities if vm.identity else {}
            for uid in uami_ids:
                if is_uami_used(uid, identities):
                    results.append({
                        "subscription": sub_id,
                        "resource_type": "VirtualMachine",
                        "resource_name": vm.name,
                        "uami_id": uid,
                    })

        # App Service
        for app in web_client.web_apps.list():
            identities = app.identity.user_assigned_identities if app.identity else {}
            for uid in uami_ids:
                if is_uami_used(uid, identities):
                    results.append({
                        "subscription": sub_id,
                        "resource_type": "AppService",
                        "resource_name": app.name,
                        "uami_id": uid,
                    })

        # Container App
        for app in container_client.container_apps.list_by_subscription():
            identities = app.identity.user_assigned_identities if app.identity else {}
            for uid in uami_ids:
                if is_uami_used(uid, identities):
                    results.append({
                        "subscription": sub_id,
                        "resource_type": "ContainerApp",
                        "resource_name": app.name,
                        "uami_id": uid,
                    })

        # ADF
        for df in adf_client.factories.list():
            identities = df.identity.user_assigned_identities if df.identity else {}
            for uid in uami_ids:
                if is_uami_used(uid, identities):
                    results.append({
                        "subscription": sub_id,
                        "resource_type": "DataFactory",
                        "resource_name": df.name,
                        "uami_id": uid,
                    })

        # Logic App
        for wf in logic_client.integration_accounts.list_by_subscription():
            identities = wf.identity.user_assigned_identities if wf.identity else {}
            for uid in uami_ids:
                if is_uami_used(uid, identities):
                    results.append({
                        "subscription": sub_id,
                        "resource_type": "LogicApp",
                        "resource_name": wf.name,
                        "uami_id": uid,
                    })

    return results

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("CMK UAMI Audit Function triggered.")

    try:
        credential = DefaultAzureCredential()
        msi_client = ManagedServiceIdentityClient(credential, SECURITY_SUBSCRIPTION_ID)

        cmk_uamis = get_cmk_uamis(msi_client)
        audit_results = find_resources_using_uami(credential, WORKLOAD_SUBSCRIPTIONS, cmk_uamis)

        return func.HttpResponse(
            body=str(audit_results),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error: {e}")
        return func.HttpResponse(f"Error: {e}", status_code=500)
