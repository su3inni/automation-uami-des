
import logging, json, requests, hashlib, hmac, base64, datetime
import azure.functions as func

from azure.identity import DefaultAzureCredential
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.web import WebSiteManagementClient

# === 설정 ===
SECURITY_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
WORKLOAD_SUBSCRIPTIONS = [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
]

WORKSPACE_ID = "your-workspace-id"
SHARED_KEY = "your-shared-key"
LOG_TYPE = "UAMIWorkloadMismatch"

# === Log Analytics 전송 함수 ===
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = f'{method}\n{str(content_length)}\n{content_type}\n{x_headers}\n{resource}'
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"

def send_to_log_analytics(customer_id, shared_key, log_type, log_entries):
    if not log_entries:
        return
    body = json.dumps(log_entries)
    date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    sig = build_signature(customer_id, shared_key, date, len(body), 'POST', 'application/json', f'/api/logs')

    uri = f"https://{customer_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': sig,
        'Log-Type': log_type,
        'x-ms-date': date
    }

    response = requests.post(uri, headers=headers, data=body)
    if response.status_code >= 400:
        logging.error(f"Failed to send log: {response.status_code} - {response.text}")

# === 네이밍 규칙 파서 ===
def parse_uami_name(uami_name):
    parts = uami_name.split("-")
    if len(parts) >= 4 and parts[-1] == "cmk":
        return parts[1].lower(), parts[2].lower()
    return None, None

def parse_resource_name(resource_name):
    parts = resource_name.split("-")
    if len(parts) >= 3:
        return parts[1].lower(), parts[2].lower()
    return None, None

# === CMK 포함된 UAMI 필터링 ===
def get_cmk_uamis(msi_client):
    all_uamis = msi_client.user_assigned_identities.list_by_subscription()
    return [u for u in all_uamis if u.name.lower().endswith("-cmk")]

# === 리소스별 UAMI 사용 현황 탐지 및 네이밍 비교 ===
def find_resources_using_uami(credential, subscriptions, cmk_uamis):
    results = []
    issues = []
    uami_id_map = {u.id.lower(): u.name for u in cmk_uamis}

    for sub_id in subscriptions:
        compute_client = ComputeManagementClient(credential, sub_id)
        web_client = WebSiteManagementClient(credential, sub_id)

        for vm in compute_client.virtual_machines.list_all():
            identities = vm.identity.user_assigned_identities if vm.identity else {}
            for uami_id in identities:
                if uami_id.lower() in uami_id_map:
                    uami_name = uami_id_map[uami_id.lower()]
                    res_sub, res_wid = parse_resource_name(vm.name)
                    uami_sub, uami_wid = parse_uami_name(uami_name)

                    if uami_wid != res_wid:
                        issues.append({
                            "resourceType": "VirtualMachine",
                            "resourceName": vm.name,
                            "uamiName": uami_name,
                            "subscriptionId": sub_id,
                            "uamiWorkloadID": uami_wid,
                            "resourceWorkloadID": res_wid,
                            "issue": "workloadID mismatch"
                        })

                    results.append({
                        "subscription": sub_id,
                        "resource_type": "VirtualMachine",
                        "resource_name": vm.name,
                        "uami_id": uami_id,
                        "uami_name": uami_name
                    })

        for app in web_client.web_apps.list():
            identities = app.identity.user_assigned_identities if app.identity else {}
            for uami_id in identities:
                if uami_id.lower() in uami_id_map:
                    uami_name = uami_id_map[uami_id.lower()]
                    res_sub, res_wid = parse_resource_name(app.name)
                    uami_sub, uami_wid = parse_uami_name(uami_name)

                    if uami_wid != res_wid:
                        issues.append({
                            "resourceType": "AppService",
                            "resourceName": app.name,
                            "uamiName": uami_name,
                            "subscriptionId": sub_id,
                            "uamiWorkloadID": uami_wid,
                            "resourceWorkloadID": res_wid,
                            "issue": "workloadID mismatch"
                        })

                    results.append({
                        "subscription": sub_id,
                        "resource_type": "AppService",
                        "resource_name": app.name,
                        "uami_id": uami_id,
                        "uami_name": uami_name
                    })

    return results, issues

# === Azure Function 진입점 ===
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("CMK UAMI Audit Function triggered.")

    try:
        credential = DefaultAzureCredential()
        msi_client = ManagedServiceIdentityClient(credential, SECURITY_SUBSCRIPTION_ID)

        cmk_uamis = get_cmk_uamis(msi_client)
        audit_results, issues = find_resources_using_uami(credential, WORKLOAD_SUBSCRIPTIONS, cmk_uamis)

        send_to_log_analytics(WORKSPACE_ID, SHARED_KEY, LOG_TYPE, issues)

        return func.HttpResponse(
            body=json.dumps(audit_results, indent=2),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error: {e}")
        return func.HttpResponse(f"Error: {e}", status_code=500)
