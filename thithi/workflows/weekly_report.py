"""WF2: báo cáo quản trị hằng tuần. Chạy theo lịch (cron/n8n) lúc 8h sáng thứ Hai.

    python -m thithi.workflows.weekly_report --user giamdoc
"""

from __future__ import annotations

import argparse
import datetime as dt
import json

from thithi.gateway.app import get_orchestrator
from thithi.mcp_servers.authz import roles_of

REQUEST = (
    "Lập báo cáo quản trị tuần cho Ban Giám đốc: doanh thu kỳ {period} theo vùng, công nợ quá hạn "
    "trên 30 ngày tính đến {as_of}, tồn kho thấp. Tổng hợp thành chỉ số, chỉ ra 3-5 điểm bất thường "
    "và việc đề xuất, kiểm duyệt rồi soạn email nháp gửi Ban Giám đốc."
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", required=True, help="tài khoản chạy báo cáo, cần vai trò ban_giam_doc")
    args = parser.parse_args()
    today = dt.date.today()
    last_month = (today.replace(day=1) - dt.timedelta(days=1)).strftime("%Y-%m")
    text = REQUEST.format(period=last_month, as_of=today.isoformat())
    orch = get_orchestrator()
    state = orch.submit(args.user, roles_of(args.user), "finance", text)
    print(json.dumps({"trace_id": state.trace_id, "status": state.status, "error": state.error}, ensure_ascii=False))


if __name__ == "__main__":
    main()
