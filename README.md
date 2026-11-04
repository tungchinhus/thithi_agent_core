# THITHI Agentic Core

Hệ thống Hybrid Agentic AI: **Claude (cloud)** lập kế hoạch và kiểm duyệt (QA), **AI local (on-premise)** là nơi duy nhất chạm vào dữ liệu nội bộ thô. Mọi thứ đi lên cloud phải qua **Gateway**: gắn nhãn dữ liệu, che PII bằng token, quét lần hai, ghi log.

Tài liệu kiến trúc: https://claude.ai/artifact/BjWAU6pDbBCfh9LGXHowhm

## Luồng một yêu cầu

1. Nhân viên gửi yêu cầu tới Gateway (`POST /v1/requests`).
2. Router chọn đường: agent `knowledge` hoặc agent có dữ liệu Tối mật chạy **thuần local**; còn lại là **lai**.
3. Đường lai: Gateway che yêu cầu rồi gửi lên Claude; Claude trả về **Plan JSON** (structured output).
4. `plan_validator` kiểm tra Plan: chỉ công cụ trong danh mục của agent, công cụ ghi phải có `approval`, công cụ nội bộ chỉ chạy local. Plan sai thì không chạy bước nào.
5. Orchestrator chạy từng bước ở local qua MCP server; bước `claude.review` gửi đầu ra **đã che** lên Claude QA. Không đạt thì Claude nhận lý do và lập Plan mới (tối đa 1 lần), Plan mới cũng phải qua `plan_validator`.
6. Bước có `approval: true` dừng chờ người duyệt (`POST /v1/approvals/{trace_id}/{step}`).
7. Gateway đổi token về giá trị thật trước khi trả kết quả cho người dùng.

## Che, đổi và tái tạo thông tin: Privacy Vault (bắt buộc chạy trên máy AI local)

Mọi việc chạm tới giá trị thật đều nằm trong dịch vụ **Privacy Vault** (`thithi/privacy/`), chạy cùng máy với LLM local, chỉ trong mạng nội bộ:

1. **Nhận diện**: biểu thức chính quy (email, SĐT, CCCD, MST, STK, số tiền), danh bạ tên đã biết, tên cột nhạy cảm (`customer_name`, `amount`...), và **NER bằng LLM local** cho tên người, tổ chức, địa chỉ trong văn bản tự do (bắt buộc; LLM local lỗi thì chặn).
2. **Che hoặc đổi** (`config/privacy.yaml`): `token` → `<KH_01>`; `pseudonym` → giá trị giả trông như thật (`Hoàng Minh Khôi`, `0900 000 001`, `lienhe01@example.vn`). Số tiền, CCCD, STK, MST luôn dùng token.
3. **Lưu ánh xạ**: SQLite, giá trị thật mã hoá Fernet, chỉ mục bằng HMAC (file CSDL không chứa giá trị thật đọc được), tự xoá sau `ttl_hours`.
4. **Quét lần hai** rồi mới trả bản đã che cho Gateway.
5. **Tái tạo**: khi kết quả quay về, chỉ Vault đổi giá trị thay thế về giá trị thật.

Gateway **không giữ ánh xạ** và không khởi động nếu thiếu `PRIVACY_URL` (trừ `THITHI_ENV=dev`). Gọi Vault lỗi hay quá giờ đều bị coi là chưa che được, nên Gateway chặn.

Giới hạn của chế độ `pseudonym`: nếu Claude viết lại giá trị giả khác đi (vd. chỉ ghi "anh Khôi"), phần đó không tái tạo được; và nếu dữ liệu thật tình cờ trùng một tên trong danh sách tên giả, tên đó sẽ không được che. Dùng `token` cho dữ liệu nhãn `mat` trở lên.

## Cấu trúc

| Thư mục | Nội dung |
| --- | --- |
| `thithi/gateway/` | Nhãn dữ liệu, kiểm tra Plan, API FastAPI, gọi Privacy Vault |
| `thithi/privacy/` | Privacy Vault: nhận diện PII + NER local, che/đổi, kho ánh xạ mã hoá, tái tạo, API riêng |
| `thithi/cloud/brain.py` | Gọi Claude để lập Plan và QA (structured output, cache system prompt, fallback khi bị từ chối) |
| `thithi/orchestrator/` | Định tuyến, thực thi Plan, chờ duyệt, danh mục công cụ, định nghĩa agent |
| `thithi/mcp_servers/` | `mcp-erp`, `mcp-docs`, `mcp-local-llm`, `mcp-notify` (MCP Python SDK 2.x) |
| `thithi/workflows/` | WF2 báo cáo tuần chạy theo lịch |
| `config/labels.yaml` | Nguồn dữ liệu → nhãn (`cong_khai`, `noi_bo`, `mat`, `toi_mat`) |
| `config/roles.yaml` | Người dùng → vai trò (dev; thật lấy từ Google Workspace/Microsoft 365) |
| `agents/*.yaml` | Mỗi phòng ban một file: công cụ được dùng, nhãn tối đa, bước cần duyệt, người duyệt |
| `config/privacy.yaml` | Chế độ `token`/`pseudonym`, thời hạn ánh xạ, bắt buộc NER |
| `deploy/` | Dockerfile, docker-compose (Gateway, Privacy Vault, vLLM, Redis) |

## Chạy thử

```bash
pip install -e ".[dev]"
pytest -q                                   # 47 test, không cần API key hay GPU

cp .env.example .env                        # điền ANTHROPIC_API_KEY, LOCAL_LLM_URL
THITHI_ENV=dev THITHI_NER=off uvicorn thithi.gateway.app:app --port 8080   # dev: Vault chạy cùng tiến trình

# WF1: hỏi đáp nội bộ, thuần local (cần LLM local đang chạy)
curl -s localhost:8080/v1/requests -H 'X-User-Id: nhanvien.an' -H 'Content-Type: application/json' \
  -d '{"agent":"knowledge","text":"Quy trình xin nghỉ phép thế nào?"}'

# WF2: báo cáo tuần (cần ANTHROPIC_API_KEY)
python -m thithi.workflows.weekly_report --user giamdoc
```

Privacy Vault chạy riêng trên máy AI local: `uvicorn thithi.privacy.api:app --port 8090` (cần `PRIVACY_VAULT_DB`, `PRIVACY_VAULT_KEY`, `PRIVACY_SERVICE_TOKEN`).

Mỗi MCP server cũng chạy độc lập được: `python -m thithi.mcp_servers.erp` (streamable-http).

## Giả định của giai đoạn 1 (cần xác nhận)

- 50–200 nhân sự, thí điểm phòng Kế toán và Hành chính, khoảng 20 người dùng.
- Một máy Linux, 1 GPU 24 GB, mô hình mở ~14B lượng tử hoá qua vLLM.
- ERP có CSDL SQL đọc qua view chỉ đọc; tài liệu trên thư mục chia sẻ hoặc Google Drive.

## Việc còn lại (đã đánh dấu TODO trong code)

- [ ] Xác thực OIDC thay cho header `X-User-Id`.
- [ ] Orchestrator gọi MCP server qua MCP client (streamable-http) thay vì gọi hàm trong cùng tiến trình.
- [ ] Trạng thái yêu cầu lưu Redis/PostgreSQL thay vì bộ nhớ.
- [ ] Backend ERP thật cho `mcp-erp`; Qdrant/pgvector + embedding local cho `mcp-docs`.
- [ ] Bộ 200 mẫu PII của công ty để nghiệm thu Gateway.
