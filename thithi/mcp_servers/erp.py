"""MCP server `mcp-erp`: đọc số liệu ERP/kế toán qua view chỉ đọc.

Mặc định chạy với dữ liệu mẫu (`ERP_BACKEND=demo`). Kết nối thật: viết một backend
`ro_query` cho SQL Server/PostgreSQL bằng tài khoản chỉ đọc, chỉ cấp quyền trên các view
`v_revenue_summary`, `v_ar_aging`, `v_inventory`. Không cho truy vấn SQL tự do.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .authz import require_role

mcp = MCPServer("mcp-erp")
MAX_ROWS = 500

_DEMO = {
    "revenue": [
        {"period": "2026-10", "group": "Miền Bắc", "revenue": 4_200_000_000},
        {"period": "2026-10", "group": "Miền Nam", "revenue": 3_100_000_000},
    ],
    "ar_aging": [
        {"customer_name": "Công ty TNHH Minh An", "invoice_no": "HD0912", "amount": 185_000_000, "days_overdue": 64},
        {"customer_name": "Công ty CP Hoà Phát Đạt", "invoice_no": "HD0877", "amount": 92_500_000, "days_overdue": 41},
        {"customer_name": "Cửa hàng Thanh Hương", "invoice_no": "HD0930", "amount": 12_000_000, "days_overdue": 12},
    ],
    "inventory": [
        {"sku": "SP-001", "warehouse": "HN", "qty": 120},
        {"sku": "SP-002", "warehouse": "HCM", "qty": 8},
    ],
}


def _result(label: str, source: str, rows: list[dict]) -> dict:
    return {"label": label, "source": source, "rows": rows[:MAX_ROWS], "truncated": len(rows) > MAX_ROWS}


@mcp.tool()
def query_revenue_summary(user_id: str, period: str, group_by: str = "region") -> dict:
    """Doanh thu tổng hợp theo kỳ (YYYY-MM), nhóm theo vùng hoặc kênh."""
    require_role(user_id, "finance", "ban_giam_doc")
    rows = [r for r in _DEMO["revenue"] if r["period"] == period]
    return _result("noi_bo", "erp.revenue_summary", rows)


@mcp.tool()
def query_ar_aging(user_id: str, as_of: str, min_days_overdue: int = 30) -> dict:
    """Công nợ phải thu quá hạn tính đến ngày as_of (YYYY-MM-DD)."""
    require_role(user_id, "finance", "ban_giam_doc")
    rows = [r for r in _DEMO["ar_aging"] if r["days_overdue"] >= min_days_overdue]
    return _result("mat", "erp.ar_aging", rows)


@mcp.tool()
def query_inventory(user_id: str, sku: str | None = None, warehouse: str | None = None) -> dict:
    """Tồn kho hiện tại theo mã hàng và kho."""
    require_role(user_id, "finance", "van_hanh", "ban_giam_doc")
    rows = [
        r
        for r in _DEMO["inventory"]
        if (sku is None or r["sku"] == sku) and (warehouse is None or r["warehouse"] == warehouse)
    ]
    return _result("noi_bo", "erp.inventory", rows)


TOOLS = [query_revenue_summary, query_ar_aging, query_inventory]

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
