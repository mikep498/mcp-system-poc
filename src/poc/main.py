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
SSH_PORT_1 = int(os.getenv("SSH_PORT_1", "22"))
SSH_PORT_2 = int(os.getenv("SSH_PORT_2", "22"))
SSH_PORT_3 = int(os.getenv("SSH_PORT_3", "22"))
SSH_USER = os.getenv("SSH_USER")
SSH_PASS = os.getenv("SSH_PASS")

AWX_URL = os.getenv("AWX_URL")
AWX_TEMPLATE_ID = os.getenv("AWX_TEMPLATE_ID")
AWX_TOKEN = os.getenv("AWX_TOKEN")

mcp = FastMCP(name="Tomcat server maintainer")

def get_ssh_client(application: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if (application == "test_application_1"):
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT_1,
            username=SSH_USER,
            password=SSH_PASS
        )
    elif (application == "test_application_2"):
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT_2,
            username=SSH_USER,
            password=SSH_PASS
        )
    else:
        client.connect(
            hostname=SSH_HOST,
            port=SSH_PORT_3,
            username=SSH_USER,
            password=SSH_PASS
        )
    return client

@mcp.tool
def get_tomcat_version(application: str, ctx: Context) -> str:
    """
    Gets the current Tomcat version running on the given application server.

    Args:
        ctx: LLM context
        application: Name of application (test_application_<number>)
    """
     
    client = get_ssh_client(application)

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
async def summarize_tomcat_logs(application: str, day: str) -> str:
    """
    Summarize Tomcat logs by date. Provide suitable solutions for exceptions, warnings or severe logs.
    Input can be:
      - "today"
      - "yesterday"
      - "N days ago" (e.g., "2 days ago")
      - Explicit date "YYYY-MM-DD"

    Args:
        day: Day from which the logs should be gathered.
        application: Name of application (test_application_<number>)
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

    client = get_ssh_client(application)
    
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
def scan_tomcat_libs(application: str) -> str:
    """
    List JARs inside Tomcat's /usr/local/tomcat/lib and check them for current vulnerabilities and CVEs. Provide suitable solutions to mitigate the vulnerabilities.

    Args:
        application: Name of application (test_application_<number>)
    """
    
    lib_path = "/usr/local/tomcat/lib/"
    cmd = f"""
    for jar in {lib_path}*.jar; do
        manifest=$(unzip -p "$jar" META-INF/MANIFEST.MF 2>/dev/null)
        
        if [[ -n "$manifest" ]]; then
            name=$(echo "$manifest" | grep -i "^Bundle-SymbolicName:" | cut -d: -f2- | xargs)
            version=$(echo "$manifest" | grep -i "^Bundle-Version:" | cut -d: -f2- | xargs)
            echo "$name | $version"
        else
            echo "$jar | (no MANIFEST.MF found)"
        fi
    done
    """
    
    client = get_ssh_client(application)
    stdin, stdout, stderr = client.exec_command(cmd)
    jar_list = stdout.read().decode()
    client.close()

    if(jar_list):
        return f"Gathered following JARs with versions: {jar_list}. They should be scanned for vulnerabilities and CVEs."
    return f"Error occured while gathering JAR information: {stderr}"


@mcp.tool
def check_tomcat_vulnerabilities(version: str) -> str:
    """
    Check Tomcat version for known CVEs using NVD API. Provide suitable solutions to mitigate the vulnerabilities.
    
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
        application: The specific application (test_application_<number>) or host to target (used for the 'limit' in AWX).
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