import os
import paramiko
from dotenv import load_dotenv
from fastmcp import FastMCP
from datetime import datetime, timedelta

load_dotenv()
SSH_HOST = os.getenv("SSH_HOST")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_USER = os.getenv("SSH_USER")
SSH_PASS = os.getenv("SSH_PASS")

mcp = FastMCP(name="Tomcat Log Analyzer")

@mcp.tool
async def summarize_tomcat_logs(day: str) -> str:
    """
    Summarize Tomcat logs by date.
    Input can be:
      - "today"
      - "yesterday"
      - "N days ago" (e.g., "2 days ago")
      - Explicit date "YYYY-MM-DD"
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

    # SSH to server
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=SSH_HOST,
        port=SSH_PORT,
        username=SSH_USER,
        password=SSH_PASS
    )
    stdin, stdout, stderr = client.exec_command(f"cat {log_path}")
    log_data = stdout.read().decode()
    err = stderr.read().decode()
    client.close()

    if err.strip():
        return f"Error reading log: {err}"
    if not log_data.strip():
        return f"No content found in {log_path}"

    # snippet = "\n".join(log_data.splitlines()[:5000])

    # # Summarize with LLM
    # summary = await ctx.sample(f"You are a log analysis assistant. Summarize Tomcat logs clearly. Logs from {date_str}:\n{snippet}\n\nSummarize key issues, errors, and warnings.")

    # return summary.text

    return "\n".join(log_data.splitlines()[:5000])

if __name__ == "__main__":
    #mcp.run(transport="http", host="127.0.0.1", port=5000)
    mcp.run(transport='stdio')