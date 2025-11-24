import os, json, hmac, hashlib, base64, datetime as dt, time
import azure.functions as func
import requests
 
from azure.identity import ManagedIdentityCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest
 
# ========= 환경변수 =========
# Log Analytics Data Collector API (DCR/DCE 없이)
LA_WORKSPACE_ID  = os.getenv("LA_WORKSPACE_ID")          # Workspace ID
LA_WORKSPACE_KEY = os.getenv("LA_WORKSPACE_KEY")         # Shared Key
LA_LOGTYPE       = os.getenv("LA_LOGTYPE", "UamiCmkCompliance")  # 최종 테이블: <LogType>_CL
 
# ARG 쿼리 스코프 (환경변수에서 주입)
SECURITY_SUB   = os.getenv("SECURITY_SUB")  # 보안 구독 ID (1개)
WORKLOAD_SUBS  = [s.strip() for s in os.getenv("WORKLOAD_SUBS","").split(",") if s.strip()]  # 워크로드 구독들
 
# 팀즈 웹훅
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
 
# ========= KQL (환경변수에서 받은 구독으로 주입) =========
def build_kql(security_sub: str, workload_subs: list[str]) -> str:
    wl = ",".join([f"'{s}'" for s in workload_subs])
    return f"""
resources
| where type =~ 'microsoft.managedidentity/userassignedidentities'
| where subscriptionId == '{SECURITY_SUB}'
| extend purpose = tostring(tags['Purpose']),
         targetSubId = tolower(tostring(tags['TargetSubscriptionId']))
| where purpose =~ 'mhsm-cmk' and isnotempty(targetSubId)
| project uamiId = id, uamiName = name, uamiRg = resourceGroup, uamiLocation = location, targetSubId, purpose
| join kind=leftouter (
    resources
    | where isnotempty(identity)
    | extend uamiMap = todynamic(identity.userAssignedIdentities)
    | where isnotempty(uamiMap)
    | mv-expand uamiRef = bag_keys(uamiMap)
    | extend usedUamiId = tostring(uamiRef)
    | project usingResourceId = id, usingResourceType = type, usingResourceName = name,
              usingResourceRg = resourceGroup, usingSubscriptionId = tolower(subscriptionId),
              usedUamiId
  ) on $left.uamiId == $right.usedUamiId
| extend compliant = iff(isempty(usingResourceId), '—(미사용)',
                         iff(usingSubscriptionId == targetSubId, '✅ OK', '❌ Audit'))
// === 구독 이름 매핑 추가 ===
| join kind=leftouter (
    resourcecontainers
    | where type == 'microsoft.resources/subscriptions'
    | project usingSubscriptionId = tolower(subscriptionId),
              usingSubscriptionName = name
  ) on usingSubscriptionId
| join kind=leftouter (
    resourcecontainers
    | where type == 'microsoft.resources/subscriptions'
    | project targetSubId = tolower(subscriptionId),
              targetSubscriptionName = name
  ) on targetSubId
| project
    ["컴플라이언스 준수"] = compliant,
    ["UAMI 이름"] = uamiName,
    // ["할당 구독명"] = targetSubscriptionName,
    ["할당 구독 ID"] = targetSubId,
    // ["사용 구독명"] = usingSubscriptionName,
    ["사용 구독ID"] = usingSubscriptionId,
    ["사용 리소스 타입"] = usingResourceType,
    ["사용 리소스 명"] = usingResourceName,
    ["사용 리소스 그룹"] = usingResourceRg
"""
 
# ========= ARG 실행 =========
def run_arg_query(cred, kql: str, security_sub: str, workload_subs: list[str]):
    # 쿼리 스코프(권한 범위)는 보안 + 워크로드 구독 전체
    subs_scope = list({security_sub, *workload_subs})
    client = ResourceGraphClient(credential=cred)
    resp = client.resources(QueryRequest(subscriptions=subs_scope, query=kql))
    return list(resp.data or [])
 
# ========= log analytics 적재를 위한 컬럼명 정규화: 한글/공백 → 영문 스키마 =========
def normalize_row(row: dict) -> dict:
    return {
        "Compliance":               row.get("컴플라이언스 준수"),
        "UamiName":                 row.get("UAMI 이름"),
        #"Assigned SubName":         row.get("할당 구독명"),
        "Assigned SubId":           row.get("할당 구독 ID"),
        #"Used SubName":             row.get("사용 구독명"),
        "Used SubId":               row.get("사용 구독ID"),
        "Used ResourceType":        row.get("사용 리소스 타입"),
        "Used ResourceName":        row.get("사용 리소스 명"),
        "Used ResourceGroup":       row.get("사용 리소스 그룹")
    }
# ========= Data Collector API 업로드 =========
def _dc_build_signature(date_rfc1123: str, content_length_bytes: int,
                        method="POST", content_type="application/json", resource="/api/logs"):
    x_headers = f"x-ms-date:{date_rfc1123}"
    string_to_hash = f"{method}\n{content_length_bytes}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(LA_WORKSPACE_KEY)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()).decode()
    return f"SharedKey {LA_WORKSPACE_ID}:{encoded_hash}"
 
def _post_chunk(chunk: list[dict]):
    if not chunk:
        return
    body = json.dumps(chunk, ensure_ascii=False)
    date = dt.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    sig  = _dc_build_signature(date, len(body.encode("utf-8")))
    uri  = f"https://{LA_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type": "application/json",
        "Log-Type": LA_LOGTYPE,                  # 최종 테이블: <LogType>_CL
        "x-ms-date": date,
        "Authorization": sig,
        # RunTime을 레코드의 TimeGenerated로 사용
        "time-generated-field": "RunTime"
    }
    for attempt in range(3):
        try:
            r = requests.post(uri, data=body.encode("utf-8"), headers=headers, timeout=20)
            if r.status_code < 300:
                return
        except Exception:
            pass
        time.sleep(2 + attempt)
 
def logging_to_la(rows: list[dict], max_chunk=1000):
    for i in range(0, len(rows), max_chunk):
        _post_chunk(rows[i:i+max_chunk])
 
# ========= 요약 & 팀즈 알림 =========
def summarize(rows: list[dict]) -> dict:
    mism = [r for r in rows if r.get("Compliance") == "❌ Audit"]
    ok   = [r for r in rows if r.get("Compliance") == "✅ OK"]
 
    def line(r):
        return (f"- **{r.get('UamiName')}** linked with **{r.get('Used ResourceName')}** \n"
        f"   - Assigned subscription: {r.get('Assigned SubId')} \n\n"
                f"   - Used subscription: {r.get('Used SubId')}"        )
    preview = "\n".join([line(r) for r in mism[:10]]) or "- (위반 없음)"
 
    return {"total": len(rows), "mismatch": len(mism), "ok": len(ok), "preview": preview}
 
def notify_teams(summary: dict):
    if not TEAMS_WEBHOOK_URL:
        return
    if summary["mismatch"] == 0 :
        return
    title = f"UAMI CMK 규정 위반 {summary['mismatch']}건" if summary["mismatch"] else "UAMI CMK 검사 결과 (위반 없음)"
    text  = (f"총 {summary['total']}건 검사\n"
             f"✅ OK: {summary['ok']} / ❌ Audit: {summary['mismatch']}\n\n"
             f"\n Audit example \n\n {summary['preview']}")
    payload = {"text": f"**{title}**\n\n{text}"}
    try:
        requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=10).raise_for_status()
    except Exception:
        pass  # 실패 시 로깅만
 
# ========= 메인 =========
def main(mytimer: func.TimerRequest) -> None:
    # 필수 체크
    if not (LA_WORKSPACE_ID and LA_WORKSPACE_KEY and SECURITY_SUB and WORKLOAD_SUBS):
        return
 
    cred = ManagedIdentityCredential(client_id=os.environ["UAMI_CLIENT_ID"])
    #cred   = DefaultAzureCredential()
    run_ts = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)
    run_id = run_ts.strftime("%Y%m%d%H%M")
 
    # 1) ARG KQL 실행 (환경변수 기반 구독 스코프)
    kql   = build_kql(SECURITY_SUB, WORKLOAD_SUBS)
    raw   = run_arg_query(cred, kql, SECURITY_SUB, WORKLOAD_SUBS)
 
    # 2) log analytics 적재를 위한 컬럼 정규화 + RunTime/RunId 주입
    rows = []
    for row in raw:
        n = normalize_row(row)
        n["RunTime"] = run_ts.isoformat()
        n["RunId"]   = run_id
        rows.append(n)
 
    # 3) Log Analytics 적재 (Collector API)
    logging_to_la(rows, max_chunk=1000)
 
    # 4) Teams 알림(선택)
    summary = summarize(rows)
    notify_teams(summary)
 
 
