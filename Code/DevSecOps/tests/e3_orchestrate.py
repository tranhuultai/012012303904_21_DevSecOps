import argparse
import csv
import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path

MODES = ("c1_seq_nocache", "c2_par_nocache", "c3_par_cache")
WORKFLOW = "e3-timing.yml"


# Chạy E3 xen kẽ: mỗi lượt dispatch đủ 3 cấu hình cùng lúc (mỗi job một VM riêng), chờ xong
# rồi mới sang lượt sau; thời gian lấy từ API jobs, không tính thời gian xếp hàng.
def gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def parse_time(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def find_run(repo, tag, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        runs = json.loads(gh("run", "list", "--repo", repo, "--workflow", WORKFLOW, "--limit", "40",
                             "--json", "databaseId,displayTitle"))
        for run in runs:
            if run["displayTitle"].endswith(f" {tag}"):
                return run["databaseId"]
        time.sleep(10)
    raise RuntimeError(f"không thấy lượt chạy có nhãn {tag}")


def wait_run(repo, run_id):
    while True:
        info = json.loads(gh("run", "view", str(run_id), "--repo", repo, "--json", "status,conclusion"))
        if info["status"] == "completed":
            return info["conclusion"]
        time.sleep(20)


def job_rows(repo, run_id, mode, rep):
    data = json.loads(gh("api", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"))
    rows = []
    for job in data["jobs"]:
        if job.get("conclusion") == "skipped" or not job.get("started_at") or not job.get("completed_at"):
            continue
        seconds = (parse_time(job["completed_at"]) - parse_time(job["started_at"])).total_seconds()
        rows.append({"run_id": run_id, "mode": mode, "rep": rep, "job": job["name"],
                     "started_at": job["started_at"], "completed_at": job["completed_at"],
                     "seconds": round(seconds, 1), "conclusion": job["conclusion"]})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=6)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    repo = os.environ["GITHUB_REPOSITORY"]
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    jobs, runs = [], []
    for rep in range(1, args.reps + 1):
        ids = {}
        for mode in MODES:
            tag = f"r{rep}-{mode}"
            gh("workflow", "run", WORKFLOW, "--repo", repo, "-f", f"mode={mode}", "-f", f"ref={args.ref}",
               "-f", f"tag={tag}")
            ids[mode] = find_run(repo, tag)
        for mode, run_id in ids.items():
            conclusion = wait_run(repo, run_id)
            rows = job_rows(repo, run_id, mode, rep)
            jobs.extend(rows)
            if rows:
                start = min(parse_time(r["started_at"]) for r in rows)
                end = max(parse_time(r["completed_at"]) for r in rows)
                runs.append({"run_id": run_id, "run_url": f"{server}/{repo}/actions/runs/{run_id}",
                             "mode": mode, "rep": rep, "conclusion": conclusion,
                             "wall_seconds": round((end - start).total_seconds(), 1),
                             "job_seconds_total": round(sum(r["seconds"] for r in rows), 1)})
            print(f"lượt {rep} {mode}: {conclusion}", flush=True)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("runs.csv", runs), ("jobs.csv", jobs)):
        with (out / name).open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    (out / "meta.json").write_text(json.dumps({"ref": args.ref, "reps": args.reps, "modes": MODES,
                                               "orchestrator_run": os.environ.get("GITHUB_RUN_ID")},
                                              indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
