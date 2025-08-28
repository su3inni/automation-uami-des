#!/usr/bin/env python3
import azure.functions as func
import logging
import json, requests, hashlib, hmac, base64, datetime,os
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.identity import ManagedIdentityCredential

cred = ManagedIdentityCredential(client_id=os.environ["UAMI_CLIENT_ID"])

# === 설정 ===
WORKLOAD_SUBSCRIPTIONS = [""]
WORKSPACE_ID = ""
SHARED_KEY = ""

# uami-<구독>-<워크로드ID>-###-cmk , <resource>-<구독>-<워크로드ID>-#### 
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

def send_log(data,tableName):
    body = json.dumps(data)
    date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(WORKSPACE_ID, SHARED_KEY, date, len(body), 'POST', 'application/json', '/api/logs')
    uri = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': tableName,
        'x-ms-date': date,
        'time-generated-field': 'timeGenerated'
    }
    try:
        r = requests.post(uri, data=body, headers=headers)
        status = "send to log analytics" if r.status_code < 300 else "recheck"
        print(f"{status} Log sent")
    except Exception as e:
        print(f" Exception sending log: {str(e)}")



def run():
# def main(mytimer: func.TimerRequest) -> None:
    #cred = DefaultAzureCredential()
    for sub_id in WORKLOAD_SUBSCRIPTIONS:
        # 1) 워크로드 내의 compute 리소스 모두 수집 > uami - des 확인
        compute = ComputeManagementClient(cred, sub_id)

        # 1-1) 워크로드에서 사용하는 des에 대해 des 와 연관된 uami 추출
        for des in compute.disk_encryption_sets.list():
            des_name = des.name
            des_subcode, des_wid = extract_subcode_workload(des_name)

            uamis = list(des.identity.user_assigned_identities.keys()) if (
                des.identity and des.identity.user_assigned_identities) else []
            if len(uamis) == 0:
                continue

            uami_mapping_valid = None
            for uami_id in uamis:
                uname = uami_id.split("/")[-1]
                # uami의 naming rule 에서 필요한 정보 추출 -> 구독, 워크로드ID
                usub, uwid = extract_subcode_workload(uname)
                # uwid 와 des의 wid 비교
                uami_mapping_valid = (uwid == des_wid)
                log_data = {
                        "timeGenerated": datetime.datetime.utcnow().isoformat() + "Z",
                        "uamiWID": uwid,
                        "desWID": des_wid,
                        "uamiMappingValid": uami_mapping_valid,
                        "uamiName":uname,
                        "desName": des_name,
                        "desSubscription":sub_id
                    }
                print("DES >>> ",log_data)
                send_log(log_data,"uamiDes")

        # 2) 워크로드 내의 모든 리소스 수집 > uami - resource 확인
        resource = ResourceManagementClient(cred, sub_id)

        # 구독 내 리소스그룹 확인
        for rg in resource.resource_groups.list():
            # 리소스 그룹 내 리소스 확인
            for res in resource.resources.list_by_resource_group(rg.name):
                identity = res.identity
                if identity and identity.type == "UserAssigned":
                    uami_dict = identity.user_assigned_identities  # 이건 dict
                    uami_ids = list(uami_dict.keys())
                
                    for uami_id in uami_ids:
                        uname = uami_id.split("/")[-1]
                        cmkcheck = uname.split("-")[-1]
                        if cmkcheck!="cmk":
                            continue

                        usub, uwid = extract_subcode_workload(uname)
                        rsub, rwid = extract_subcode_workload(res.name)
                        uami_mapping_valid = (uwid == rwid)

                        log_data = {
                                "timeGenerated": datetime.datetime.utcnow().isoformat() + "Z",
                                "uamiWID": uwid,
                                "resourceWID": rwid,
                                "uamiMappingValid": uami_mapping_valid,
                                "uamiName": uname,
                                "resourceName": res.name,
                                "resourceType": res.type,
                                "resourceSubscription": sub_id
                        }
                        print("all >>> >>> ",log_data)
                        send_log(log_data,"uamiResource")

run()
