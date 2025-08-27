
import json
import subprocess
import logging

SECURITY_SUBSCRIPTION_ID = ""
WORKLOAD_SUBSCRIPTIONS = [""]

def run_az_cli(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL)
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {command}")
        return []

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

def get_cmk_uamis(subscription_id):
    cmd = f'az identity list --subscription {subscription_id} --query "[?ends_with(name, '-cmk')]" -o json'
    return run_az_cli(cmd)

def get_vms(subscription_id):
    cmd = f'az vm list --subscription {subscription_id} -o json'
    return run_az_cli(cmd)

def main():
    uami_mismatch_logs = []

    # 1. 보안 구독에서 CMK 포함된 UAMI 수집
    cmk_uamis = get_cmk_uamis(SECURITY_SUBSCRIPTION_ID)
    uami_id_map = {u['id'].lower(): u['name'] for u in cmk_uamis}

    for sub_id in WORKLOAD_SUBSCRIPTIONS:
        logging.info(f"Processing subscription: {sub_id}")
        vms = get_vms(sub_id)

        for vm in vms:
            vm_name = vm.get("name")
            identities = vm.get("identity", {}).get("userAssignedIdentities", {})
            for uami_id in identities.keys():
                if uami_id.lower() in uami_id_map:
                    uami_name = uami_id_map[uami_id.lower()]
                    uami_sub, uami_wid = parse_uami_name(uami_name)
                    res_sub, res_wid = parse_resource_name(vm_name)

                    if uami_wid != res_wid:
                        uami_mismatch_logs.append({
                            "subscriptionId": sub_id,
                            "resourceType": "VirtualMachine",
                            "resourceName": vm_name,
                            "uamiName": uami_name,
                            "uamiWorkloadID": uami_wid,
                            "resourceWorkloadID": res_wid,
                            "issue": "workloadID mismatch"
                        })

    print(json.dumps(uami_mismatch_logs, indent=2))

if __name__ == "__main__":
    main()
