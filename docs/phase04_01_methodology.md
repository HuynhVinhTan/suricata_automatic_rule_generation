# Phase 04.1.2 — Data Quality Profiling: phương pháp và nghiệm thu

## 1. Bài toán

Ba bộ dữ liệu UNSW-NB15, CIC-IDS2017 và CTU-13 có cấu trúc và ý nghĩa nhãn khác nhau. Huấn luyện trực tiếp khi chưa kiểm kê đầy đủ có nguy cơ thất bại vì giá trị thiếu/vô hạn, cột trùng, dữ liệu trùng lặp hoặc rò rỉ giữa các tập. Giai đoạn này **khảo sát**, không tự động xóa dòng/cột hoặc cân bằng lớp.

## 2. Cơ sở dữ liệu đầu vào đã quan sát

- UNSW-NB15: `training-set.csv` và `testing-set.csv`, mỗi file 45 cột, có `label` và `attack_cat`.
- CIC-IDS2017 Friday DDoS: 79 cột, cột nhãn có khoảng trắng đầu (` Label`); `Fwd Header Length` xuất hiện nhiều lần sau khi chuẩn hóa tên cột.
- CTU-13: file `.binetflow` 15 cột, có `Label`.
- Suricata sample JSON đã có nhưng **không dùng** để suy luận sự tương đương feature ở giai đoạn này.

Đây là thông tin từ bước Dataset Inventory; chưa thay thế được thống kê toàn bộ bản ghi.

## 3. Lựa chọn kỹ thuật và giải thích

| Thiết kế | Vì sao chọn | Giới hạn |
|---|---|---|
| Đọc CSV từng dòng với `csv.reader` | Không cần RAM đủ chứa toàn bộ dataset; giữ nguyên tên cột gốc | Chậm hơn xử lý vector hóa |
| Không dùng pandas ở bước profile | Không phụ thuộc version thư viện; tránh pandas tự đổi tên cột trùng | Chỉ thống kê literal, chưa suy luận kiểu dữ liệu |
| SHA256 mỗi file gốc | Nhận diện bản dữ liệu chính xác để tái lập | Hash không tự chứng minh dataset có nguồn đáng tin cậy |
| Ghi dấu vân tay dòng vào SQLite tạm | Đếm bản ghi trùng với bộ nhớ hạn chế | Có chi phí thời gian và dung lượng đĩa tạm |
| Bỏ `id` khi so sánh dòng UNSW | `id` nhân tạo có thể che giấu dòng trùng | Hai record khác nguồn có thể tình cờ trùng features |
| So sánh feature trùng bỏ `id`, `label`, `attack_cat` | Tìm mẫu feature giống nhau nhưng nhãn có thể khác | Chỉ nhận diện giá trị giống chính xác sau trim chuỗi |
| So sánh UNSW train–test | Phát hiện feature vector xuất hiện trong cả hai phần chia có sẵn | Chưa kết luận đây là leakage mà không xem split protocol |
| Giữ số lượng nhãn nguyên gốc | Bảo toàn nhãn gốc phục vụ thiết kế label mapping | Nhãn CTU cần phân tích ngữ nghĩa trước khi gán benign/attack |
| Dò `NaN`, `Inf`, chuỗi null và dòng sai số cột | Phát hiện đầu vào làm lỗi mô hình và parsing | Chưa phát hiện ngoại lệ định lượng hoặc sai đơn vị |
| Không ghi dữ liệu mẫu vào báo cáo | Tránh xuất nội dung packet/flow có thể mang IP | Giảm thuận tiện khi debug dòng lỗi, dùng số thứ tự dòng thay thế |

**Lưu ý:** Không đồng nhất `sbytes` với `flow.bytes_toserver`, hoặc `TotPkts` với packet counter của Suricata, nếu chưa xác minh cách tính, chiều và thời gian quan sát.

## 4. Files và lệnh

Chép:
- `scripts/phase04_01_data_quality.py`
- `tests/test_phase04_data_quality.py`

Chạy trong repository `D:\suricata-ai-project`:

```powershell
python -m unittest discover -s tests -p 'test_phase04_data_quality.py' -v
python .\scripts\phase04_01_data_quality.py --project-root . --max-rows 1000
python .\scripts\phase04_01_data_quality.py --project-root .
```

**Cần chạy toàn bộ không có `--max-rows` để dùng làm kết luận**; `--max-rows` chỉ là bước kiểm tra nhanh.

Output:
- `results/phase04/data-quality/quality_report.md`
- `results/phase04/data-quality/quality_summary.json`

Các file gốc dưới `data/raw/` không bị sửa; công cụ tạo SQLite tạm rồi tự dọn khi hoàn tất.

## 5. Tiêu chí chấp nhận Phase 04.1.2

- [ ] Đủ bốn dataset được quét toàn bộ (`complete=true`; `max_rows_per_dataset=null`).
- [ ] Không có lỗi đọc/giải mã; mọi dòng sai số cột đã được thống kê.
- [ ] Ghi nhận nhãn và phân phối lớp cho từng bộ, **không gộp chung**.
- [ ] Có thống kê `NaN`, `Inf`, missing theo cột; quyết định xử lý dựa trên vị trí và tỷ lệ.
- [ ] Kiểm tra cột trùng CIC: hai cột trùng tên có thực sự trùng giá trị hay không.
- [ ] Kiểm tra UNSW train/test overlap, báo cáo và đề xuất biện pháp chống leakage.
- [ ] Phân tích giới hạn định nghĩa feature và mapping với Suricata trước preprocessing.

## 6. Nội dung báo cáo khi chốt bước

1. Đã chạy công cụ gì, với bộ dataset SHA256 nào.
2. Tổng số dòng, tỷ lệ label, missing/Inf/NaN, trùng lặp, dòng lỗi.
3. Những vấn đề có ảnh hưởng thực tế đến huấn luyện/inference.
4. Phương án xử lý đề xuất và lý do; phương án chưa chọn.
5. Giới hạn của phép kiểm tra (literal-only, chưa semantic/near duplicate).
6. Điều kiện chuyển sang Phase 04.2 — Cleaning & EDA, cùng dữ liệu/hành động cần bổ sung.

**Không trình bày kết quả giả lập của unit test như là thống kê dữ liệu thật.**
