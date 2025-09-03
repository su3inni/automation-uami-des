#!/usr/bin/env python3
import azure.functions as func
import logging
import json, requests, hashlib, hmac, base64, datetime, os

from azure.identity import ManagedIdentityCredential
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

# ======== Auth / Env ========
# SDK 호출용 UAMI(Client ID 지정)
cred = ManagedIdentityCredential(client_id=os.environ["UAMI_CLIENT_ID"])
sub_client = SubscriptionClient(cred)

WORKSPACE_ID = os.environ["WORKSPACE_ID"]
SHARED_KEY   = os.environ["SHARED_KEY"]

# (선택) 대상 구독을 환경변수로 제한하고 싶으면 설정.
# 미설정 시, 현재 자격 증명이 접근 가능한 모든 구독을 자동으로 탐색.
subs_env = os.environ.get("WORKLOAD_SUBSCRIPTIONS", "")
ENV_WORKLOAD_SUBS = [s.strip().strip("'").strip('"') for s in subs_env.split(",") if s.strip()]

# ======== Helpers ========
def extract_subcode_from_uami(name: str):
    """uami-<subcode>-<wid>-###-cmk → <subcode>만 추출 (없으면 None)"""
    parts = name.split("-")
    return parts[1].lower() if len(parts) >= 3 else None

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"

def send_log(data, tableName):
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
        status = "send to log analytics" if r.status_code < 300 else f"recheck (status={r.status_code})"
        logging.info(status)
    except Exception as e:
        logging.info(f"Exception sending log: {str(e)}")

def get_subscription_name_cache():
    """구독 ID → 구독명 캐시용 클로저 리턴"""
    cache = {}
    def _get_name(sid: str) -> str:
        if sid in cache:
            return cache[sid]
        sub = sub_client.subscriptions.get(sid)
        cache[sid] = sub.display_name
        return cache[sid]
    return _get_name

def list_accessible_subscriptions() -> list[str]:
    """자격증명이 접근 가능한 구독 리스트. ENV로 제한되어 있으면 그 값 사용."""
    if ENV_WORKLOAD_SUBS:
        return ENV_WORKLOAD_SUBS
    return [s.subscription_id for s in sub_client.subscriptions.list()]

def list_cmk_uamis(cred, subs: list[str]) -> list[dict]:
    """
    각 구독의 UAMI를 조회해 이름이 ...-cmk 로 끝나는 것만 반환.
    반환 항목: {id,name,subscriptionId,principalId}
    """
    out = []
    for sub in subs:
        try:
            msi = ManagedServiceIdentityClient(cred, sub)
            for idn in msi.user_assigned_identities.list_by_subscription():
                name = idn.name or ""
                if not name.endswith("-cmk"):
                    continue
                out.append({
                    "id": (idn.id or "").lower(),
                    "name": name,
                    "subscriptionId": sub,
                    "principalId": str(getattr(idn, "principal_id", getattr(idn, "principalId", None)) or "")
                })
        except Exception as e:
            logging.warning(f"[{sub}] list_cmk_uamis error: {e}")
    return out

def chunk(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i+size]

def query_resources_by_uamis(cred, subscriptions: list[str], uami_ids: list[str]) -> list[dict]:
    """
    ARG로 주어진 UAMI ID들에 연결된 리소스를 한 번에 조회.
    반환: [{uamiId, resourceId, resourceType, resourceName, resourceGroup, subscriptionId}, ...]
    """
    if not uami_ids:
        return []

    client = ResourceGraphClient(cred)
    results = []

    # 너무 많은 ID를 한 번에 넣으면 쿼리 길이 제한에 걸릴 수 있어 chunk 처리
    for group in chunk(uami_ids, 500):
        # datatable 구성
        values = ", ".join([f'"{u}"' for u in group])
        query = f"""
let target = datatable(uamiId:string) [{values}];
resources
| where isnotempty(identity) and tolower(tostring(identity.type)) has "userassigned"
| extend uamiIds = bag_keys(identity.userAssignedIdentities)
| mv-expand uamiId = uamiIds
| project uamiId = tolower(uamiId), resourceId = id, resourceType = type,
          resourceName = name, resourceGroup, subscriptionId
| join kind=inner target on uamiId
"""
        req = QueryRequest(
            subscriptions=subscriptions,
            query=query,
            options=QueryRequestOptions(result_format="objectArray", top=1000)
        )

        while True:
            resp = client.resources(req)
            data = resp.data or []
            results.extend(data)
            st = getattr(resp, "skip_token", None)
            if not st:
                break
            req.options.skip_token = st

    return results

# ======== Timer Trigger Entry ========
def main(mytimer: func.TimerRequest) -> None:
    logging.info("UAMI->Resource 역매핑 시작")

    # 1) 대상 구독 목록
    target_subs = list_accessible_subscriptions()
    if not target_subs:
        logging.warning("접근 가능한 구독이 없습니다.")
        return

    # 2) 모든 구독에서 '-cmk' UAMI 수집
    uamis = list_cmk_uamis(cred, target_subs)
    if not uamis:
        logging.info("'-cmk' UAMI가 없습니다.")
        return

    # uamiId -> {name, principalId, subscriptionId} 맵
    uami_index = {u["id"]: u for u in uamis}
    uami_ids = list(uami_index.keys())

    # 3) ARG로 해당 UAMI들을 실제로 참조하는 리소스 조회(전 구독 범위)
    rows = query_resources_by_uamis(cred, target_subs, uami_ids)

    # 4) 비교 및 Log Analytics 전송
    get_sub_name = get_subscription_name_cache()
    sent = 0

    for r in rows:
        try:
            uami_id = r["uamiId"]
            res_id  = r["resourceId"]
            res_type = r.get("resourceType")
            res_name = r.get("resourceName") or res_id.split("/")[-1]
            rsub_id  = r.get("subscriptionId") or res_id.split("/")[2]
            rsub_name = get_sub_name(rsub_id)

            # 구독 GUID의 두 번째 세그먼트 (기존 로직 유지)
            rsub_id_split = rsub_id.split("-")
            rsub_compare  = rsub_id_split[1] if len(rsub_id_split) >= 2 else ""

            # UAMI 네이밍에서 subcode 추출
            uami_meta = uami_index.get(uami_id, {})
            uami_name = uami_meta.get("name", "")
            usub = extract_subcode_from_uami(uami_name)

            uami_mapping_valid = bool(usub and rsub_compare and (usub in rsub_compare))

            log_data = {
                "timeGenerated": datetime.datetime.utcnow().isoformat() + "Z",
                "uamiName": uami_name,
                "uamiId": uami_id,
                "uamiPrincipalId": uami_meta.get("principalId", ""),
                "resourceName": res_name,
                "resourceId": res_id,
                "resourceType": res_type,
                "uamiMappingValid": uami_mapping_valid,
                "resourceSubscription": rsub_id,
                "resourceSubscriptionName": rsub_name
            }

            send_log(log_data, "Uami2Resource")
            sent += 1
        except Exception as e:
            logging.warning(f"row 처리 중 오류: {e}")

    logging.info(f"완료: UAMI {len(uamis)}개, 참조 리소스 {len(rows)}건, 로그 전송 {sent}건")
