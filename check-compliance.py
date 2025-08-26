# python 3.9 azure-identity==1.13.0 \ azure-mgmt-compute==29.1.0 \ azure-mgmt-resource==21.1.0
#!/usr/bin/env python3
import json, requests, hashlib, hmac, base64, datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient

# === 설정 ===
WORKLOAD_SUBSCRIPTIONS = [
    ""
]
WORKSPACE_ID = ""
SHARED_KEY = ""
LOG_TYPE = "DESAudit"

def extract_subcode_workload(name):
    parts = name.split("-")
    return (parts[1].lower(), parts[2].lower()) if len(parts) >= 3 else (None, None)

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"

def send_log(data):
    body = json.dumps(data)
    date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(WORKSPACE_ID, SHARED_KEY, date, len(body), 'POST', 'application/json', '/api/logs')
    uri = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': LOG_TYPE,
        'x-ms-date': date,
        'time-generated-field': 'timeGenerated'
    }
    try:
        r = requests.post(uri, data=body, headers=headers)
        status = "send to log analytics" if r.status_code < 300 else "recheck"
        print(f"{status} Log sent: {data['desName']}")
    except Exception as e:
        print(f" Exception sending log: {str(e)}")

def find_resources_using_des(resource_client, des_id):
    matched = []
    for rg in resource_client.resource_groups.list():
        for res in resource_client.resources.list_by_resource_group(rg.name):
            try:
                res_full = resource_client.resources.get_by_id(res.id, api_version="2023-03-01")
                props = getattr(res_full, 'properties', None)
                encryption = getattr(props, 'encryption', None)
                if encryption and hasattr(encryption, 'diskEncryptionSetId'):
                    des_ref = getattr(encryption, 'diskEncryptionSetId')
                    if des_ref and des_id.lower() in des_ref.lower():
                        matched.append({
                            "name": res.name,
                            "type": res.type,
                            "resourceGroup": rg.name
                        })
            except Exception:
                continue
    return matched

def run():
    cred = DefaultAzureCredential()
    for sub_id in WORKLOAD_SUBSCRIPTIONS:
        compute = ComputeManagementClient(cred, sub_id)
        resource = ResourceManagementClient(cred, sub_id)

        for rg in resource.resource_groups.list():
            for des in compute.disk_encryption_sets.list(rg.name):
                des_name = des.name
                des_subcode, des_wid = extract_subcode_workload(des_name)

                uamis = list(des.identity.user_assigned_identities.keys()) if (
                    des.identity and des.identity.user_assigned_identities) else []
                if len(uamis) == 0:
                    continue

                linked_resources = find_resources_using_des(resource, des.id)

                for uami_id in uamis:
                    if uami_id:
                        uname = uami_id.split("/")[-1]
                        _, uwid = extract_subcode_workload(uname)
                        uami_mapping_valid = (uwid == des_wid)

                    for res in linked_resources or [None]:
                        if res:
                            rsub, rwid = extract_subcode_workload(res['name'])
                            resource_mapping_valid = (rsub == des_subcode and rwid == des_wid)
                            resource_id = f"/subscriptions/{sub_id}/resourceGroups/{res['resourceGroup']}/providers/{res['type']}/{res['name']}"
                        else:
                            resource_mapping_valid = None
                            resource_id = None

                        log_data = {
                            "timeGenerated": datetime.datetime.utcnow().isoformat() + "Z",
                            "subscriptionId": sub_id,
                            "desName": des_name,
                            "uamiId": uami_id,
                            "uamiMappingValid": uami_mapping_valid,
                            "resourceId": resource_id,
                            "resourceMappingValid": resource_mapping_valid
                        }
                        send_log(log_data)

run()
