import json
import os
import sys
import time
import paramiko
import requests
import re
from dotenv import load_dotenv
from fastmcp import FastMCP, Context
from datetime import datetime, timedelta

load_dotenv()
SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_USER = os.getenv("SSH_USER")
SSH_PASS = os.getenv("SSH_PASS")

AWX_URL = os.getenv("AWX_URL")
AWX_TEMPLATE_ID = os.getenv("AWX_TEMPLATE_ID")
AWX_TOKEN = os.getenv("AWX_TOKEN")

mcp = FastMCP(name="Tomcat server maintainer")

def get_ssh_client() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=SSH_HOST,
        port=SSH_PORT,
        username=SSH_USER,
        password=SSH_PASS
    )
    return client

@mcp.tool
def get_tomcat_version(ctx: Context) -> str:
    """
    Gets the current Tomcat version running on the server.

    Args:
        ctx: LLM context
    """
     
    client = get_ssh_client()

    stdin, stdout, stderr = client.exec_command("/usr/local/tomcat/bin/version.sh")
    version_output = stdout.read().decode() + stderr.read().decode()
    client.close()

    match = re.search(r"Apache Tomcat/([0-9.]+)", version_output)
    if not match:
        ctx.warning(f"Could not detect Tomcat version:\n{version_output}") 
        return ""
    version = match.group(1)

    return version

@mcp.tool
async def summarize_tomcat_logs(day: str) -> str:
    """
    Summarize Tomcat logs by date.
    Input can be:
      - "today"
      - "yesterday"
      - "N days ago" (e.g., "2 days ago")
      - Explicit date "YYYY-MM-DD"

    Args:
        day: Day from which the logs should be gathered.
    """
    day_lower = day.lower().strip()

    # Resolve relative date
    if day_lower == "today":
        date_str = datetime.today().strftime("%Y-%m-%d")
    elif day_lower == "yesterday":
        date_str = (datetime.today() - timedelta(days=1)).strftime("%Y-%m-%d")
    elif "days ago" in day_lower:
        try:
            n = int(day_lower.split()[0])
            date_str = (datetime.today() - timedelta(days=n)).strftime("%Y-%m-%d")
        except Exception:
            return f"Could not parse relative date: {day}"
    else:
        # assume direct YYYY-MM-DD
        try:
            # validate date format
            datetime.strptime(day, "%Y-%m-%d")
            date_str = day
        except ValueError:
            return f"Invalid date format: {day}. Use YYYY-MM-DD."

    log_path = f"/usr/local/tomcat/logs/catalina.{date_str}.log"

    client = get_ssh_client()
    
    stdin, stdout, stderr = client.exec_command(f"cat {log_path}")
    log_data = stdout.read().decode()
    err = stderr.read().decode()
    client.close()

    if err.strip():
        return f"Error reading log: {err}"
    if not log_data.strip():
        return f"No content found in {log_path}"

    return "\n".join(log_data.splitlines()[:5000])

@mcp.tool
def scan_tomcat_libs() -> str:
    """
    List JARs inside Tomcat's /usr/local/tomcat/lib and check them against OSV.dev.
    """
    
    lib_path = "/usr/local/tomcat/lib/"
    cmd = f"ls -1 {lib_path} | grep .jar || echo 'No JARs found'"
    
    client = get_ssh_client()
    stdin, stdout, stderr = client.exec_command(cmd)
    jar_list = stdout.read().decode().splitlines()
    client.close()
    
    if not jar_list or "No JARs" in jar_list[0]:
        return f"No JARs found in {lib_path}"
    
    results = []
    for jar in jar_list[:15]:  # check first 15 JARs
        package_name = jar.split("-")[0]
        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": package_name, "ecosystem": "Maven"}},
                timeout=10
            )
            data = resp.json()
            if "vulns" in data:
                vulns = [v["id"] for v in data["vulns"]]
                results.append(f"{jar}: {', '.join(vulns)}")
        except Exception as e:
            results.append(f"{jar}: Error {e}")
    
    if not results:
        return "No known vulnerabilities detected in Tomcat libs."
    
    return "Detected vulnerabilities in Tomcat libs:\n" + "\n".join(results)


@mcp.tool
def check_tomcat_vulnerabilities(version: str) -> str:
    """
    Check Tomcat version for known CVEs using NVD API. Offer to help if version is vulnerable.
    
    Args:
        version: The Tomcat version.
    """
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
    except Exception as e:
        return f"Error querying NVD: {e}"

    if "vulnerabilities" not in data or not data["vulnerabilities"]:
        return f"✅ Tomcat {version} appears clean (no CVEs found)."

    results = []
    for vuln in data["vulnerabilities"][:5]:
        cve_id = vuln["cve"]["id"]
        description = vuln["cve"]["descriptions"][0]["value"]
        results.append(f"{cve_id}: {description}")

    return f"⚠️ Tomcat {version} CVEs:\n" + "\n".join(results)

@mcp.tool
def update_tomcat_version(ctx: Context, version: str, application: str, poll_interval: int = 15, timeout: int = 1800):
    """
    Launches an AWX job to update Tomcat and waits for it to complete. Check the tomcat version on the server afterwards.

    Args:
        ctx: LLM context
        version: The target Tomcat version.
        application: The specific application or host to target (used for the 'limit' in AWX).
        poll_interval: Seconds to wait between status checks.
        timeout: Maximum seconds to wait for the job to complete.
    """
    headers = {
        "Authorization": f"Bearer {AWX_TOKEN}",
        "Content-Type": "application/json"
    }

    # 1. Launch the Job
    launch_url = f"{AWX_URL}/api/v2/job_templates/{AWX_TEMPLATE_ID}/launch/"
    payload = {
        "extra_vars": {"tomcat_version": version}
    }
    if application:
        payload["limit"] = application

    try:
        launch_response = requests.post(launch_url, headers=headers, data=json.dumps(payload))
        launch_response.raise_for_status()
        launch_data = launch_response.json()
        job_id = launch_data.get("job")

        if not job_id:
            return "Error: Could not retrieve job ID after launching."

        ctx.info(f"Successfully launched AWX job with ID: {job_id}. Waiting for completion...")

    except requests.exceptions.RequestException as e:
        return f"An error occurred while launching the job: {e}"

    # 2. Poll for Job Completion
    job_status_url = f"{AWX_URL}/api/v2/jobs/{job_id}/"
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            status_response = requests.get(job_status_url, headers=headers)
            status_response.raise_for_status()
            status_data = status_response.json()
            current_status = status_data.get("status")

            if current_status in ["successful", "failed", "error", "canceled"]:
                return {
                    "job_id": job_id,
                    "status": current_status,
                    "finished": status_data.get("finished"),
                    "elapsed": status_data.get("elapsed"),
                    "message": f"Job {job_id} finished with status: {current_status}."
                }

            time.sleep(poll_interval)

        except requests.exceptions.RequestException as e:
            return f"An error occurred while checking job status for job {job_id}: {e}"

    return f"Job {job_id} timed out after {timeout} seconds. Last known status was '{current_status}'."

if __name__ == "__main__":
    #mcp.run(transport="http", host="127.0.0.1", port=5000)
    mcp.run(transport='stdio')