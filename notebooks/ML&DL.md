# Quyết định kiến trúc: Phân chia nhiệm vụ ML và DL

**Đề tài:** Sinh tự động luật Suricata dựa trên mô hình học máy phát hiện tấn công mới\
**Trạng thái:** Thiết kế đề xuất; chưa phải kết quả thực nghiệm\
**Giai đoạn:** Phase 04 — Thiết kế dữ liệu, đặc trưng và phương pháp

## 1. Bài toán và nguyên tắc

Mục tiêu của đề tài không chỉ là dự đoán `Normal`/`Attack`, mà là phát hiện hành vi đáng ngờ, chuyển **bằng chứng mạng có thể diễn đạt bằng luật** thành luật Suricata ứng viên và đo được tác dụng của luật trên dữ liệu kiểm thử độc lập.

Không huấn luyện hai mô hình trên cùng một tập hàng, cùng đặc trưng, cùng mục tiêu rồi tuyên bố chúng bổ trợ nhau. Thay vào đó, chúng hoạt động ở **hai độ phân giải**:

| Khía cạnh | ML — Isolation Forest (ứng viên) | DL — GRU Autoencoder (ứng viên) |
|---|---|---|
| Câu hỏi | *Flow riêng lẻ này khác thường đến mức nào?* | *Chuỗi hành vi của một nguồn trong cửa sổ thời gian có bất thường không?* |
| Đơn vị | Flow | Chuỗi các flow / các lát thời gian theo nguồn |
| Input | Đặc trưng flow có thể trích xuất từ Suricata | Chuỗi đặc trưng tổng hợp: nhịp kết nối, số cổng đích duy nhất, số flow lỗi/thành công, số byte/packet theo khoảng thời gian... |
| Output | `flow_anomaly_score`, `flow_id`, feature đóng góp cần kiểm chứng | `sequence_anomaly_score`, `source_id`, khoảng thời gian và đặc trưng chuỗi |
| Thế mạnh nghiên cứu | Cảnh báo sơ bộ từng flow, ít yêu cầu ngữ cảnh | Nhận diện hành vi phân tán qua nhiều flow, ví dụ quét cổng chậm |
| Giới hạn | Một flow có thể bình thường dù nằm trong chuỗi nguy hiểm | Cần timestamp, khóa định danh nguồn và đủ chuỗi Normal hợp lệ |

Đây là **phân chia trách nhiệm kiến trúc**, chưa phải bằng chứng rằng Isolation Forest hoặc GRU Autoencoder đạt hiệu năng cao nhất. Có thể so sánh với baseline thay thế sau khi hoàn thành dữ liệu và feature mapping.

## 2. Luồng triển khai dự kiến

```text
VM1 Suricata EVE → Filebeat → VM3 Logstash/Elasticsearch
                              │
                              ▼
                     Event / Flow Adapter
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
             Per-flow features      Event-time windows
                    │               theo nguồn / tài sản
                    ▼                   │
          ML: Isolation Forest          ▼
                    │             DL: GRU Autoencoder
                    └─────────┬─────────┘
                              ▼
                  Evidence Correlation Engine
                  (có thể nhận ML hoặc DL
                  hoặc cả hai, không ép đồng thuận)
                              ▼
              Kiểm tra đủ bằng chứng sinh luật
                              ▼
                  Rule Template Generator
                              ▼
          Cú pháp → Replay/benign tests → Review
                              ▼
                Luật được phê duyệt cho Suricata
```

### Không nhầm tương trợ với cơ chế 'cả hai phải đồng ý'

- **ML cao, DL thấp:** flow bất thường đơn lẻ; lưu bằng chứng và theo dõi, *không mặc định* sinh luật.
- **ML thấp, DL cao:** chuỗi đáng ngờ, chẳng hạn quét chậm; vẫn mở điều tra dù nhiều flow riêng lẻ có vẻ bình thường.
- **Cả hai cao:** tăng ưu tiên điều tra và kiểm thử rule candidate.
- **Cả hai thấp:** không đủ bằng chứng mô hình; các luật Suricata hiện hữu vẫn hoạt động độc lập.

Kết luận sinh luật **không** chỉ dựa vào phép cộng hoặc lấy trung bình hai điểm bất thường. Phải có điều kiện hành vi xác minh được bằng dữ liệu mạng, điều kiện hỗ trợ bởi đúng phiên bản Suricata và thử nghiệm false positive.

## 3. Kiểm tra khả năng thực hiện với dataset đã có

| Dataset | Dùng cho ML per-flow? | Dùng cho DL chuỗi theo nguồn? | Ghi chú |
|---|---|---|---|
| UNSW-NB15 training/testing | Có, sau khi chọn feature tương thích và kiểm tra leakage | **Không đủ trực tiếp**: bản CSV hiện có không chứa timestamp + src/dst IP để xây chuỗi host theo thời gian | `id` không được coi là timestamp hoặc ID nguồn |
| CIC-IDS2017 Friday DDoS CSV hiện có | Có thể đánh giá độc lập sau mapping | **Chưa đủ trực tiếp**: bản CSV đã kiểm tra không có trường timestamp + IP rõ ràng | Nếu tải thêm PortScan CSV, phải xác minh cấu trúc; không giả định có các cột này |
| CTU-13 `.binetflow` | Có thể, lưu ý nhãn | **Có khả năng** xây chuỗi: `StartTime`, `SrcAddr`, `DstAddr`; cần kiểm tra chất lượng và ground truth | `Background` không được tự coi là `Normal` |
| Suricata EVE trên lab | Có, cần xác minh trường thực sự xuất hiện | **Dữ liệu trọng tâm**: timestamp, flow_id, src_ip, dest_ip và các thống kê flow | Thu thập Normal đủ đa dạng trước khi fit DL |

**Điều kiện nghiệm thu DL:** Có đủ dữ liệu chuỗi được nhóm đúng nguồn và thời gian; train/test tách theo phiên, thời gian hoặc kịch bản phù hợp; đánh giá tránh chồng lặp cửa sổ giữa các tập.

## 4. Dữ liệu, feature và diễn giải

- **ML:** chỉ dùng feature Suricata có thể tạo ổn định. Mapping `sbytes` → `flow.bytes_toserver` là *giả thuyết cần xác minh*, không mặc định đồng nghĩa.
- **DL:** tổng hợp flow theo nguồn và theo thời gian sự kiện. Ví dụ mỗi bước mô tả 10 giây, một cửa sổ có thể gồm 6 bước (60 giây); đây là **giả định ban đầu cần thử nghiệm**, không phải ngưỡng đã xác nhận.
- **Nguồn:** cần phân biệt địa chỉ client/initiator thực tế với địa chỉ chiều truyền trong EVE; xử lý lại sự kiện trùng lặp theo `flow_id` và quy tắc chọn bản thống kê cuối.
- **Đầu ra:** hai điểm số có thang đo khác nhau; cần hiệu chuẩn trên validation riêng, không cộng thô hoặc coi chúng là xác suất tấn công.

## 5. Sinh luật: nhiệm vụ của một engine riêng

ML và DL cung cấp **bằng chứng**, không trực tiếp viết luật từ tensor hoặc điểm số. Bộ sinh luật dùng các biểu mẫu có kiểm soát, gồm hành vi quan sát được, chiều kết nối, giao thức, cổng, giới hạn thời gian/tần suất nếu cú pháp hỗ trợ.

Quy trình tối thiểu:

1. Lập bản ghi bằng chứng và đối chiếu sự kiện nguồn.
2. Xác định mẫu luật nào có thể biểu diễn đúng hành vi, tránh viết luật theo các biến DL ẩn hoặc logic không được Suricata hỗ trợ.
3. Sinh **luật ứng viên**, chưa triển khai tự động.
4. Kiểm tra cú pháp trên cùng phiên bản Suricata thực tế (VM1 hiện là 8.0.3).
5. Phát lại PCAP tấn công **và** benign độc lập; đo số lần phát hiện, false positive và độ trễ.
6. Chỉ áp dụng luật khi đạt điều kiện nghiệm thu và đã được phê duyệt; có cơ chế rollback.

**Lưu ý phiên bản:** Tài liệu Suricata 8.0.3 mô tả `detection_filter: track ..., count ..., seconds ...` mà **không mô tả tùy chọn `unique_on dst_port`**. Không dùng tính năng ở tài liệu của phiên bản mới hơn khi chưa kiểm tra trên VM1. Nếu phải đếm *số cổng đích khác nhau*, bộ phân tích ngoài Suricata có thể tính chỉ số này để đánh giá, nhưng không được giả định một luật 8.0.3 có thể biểu diễn đúng phép đếm đó.

## 6. Thí nghiệm chứng minh hai mô hình bổ trợ

So sánh ít nhất bốn cấu hình, giữ nguyên tập kiểm thử và phương pháp tách dữ liệu:

| Hệ thống | Ý nghĩa |
|---|---|
| A. Suricata rule baseline | Mốc so sánh bộ luật có sẵn |
| B. Suricata + ML flow detector | Lợi ích của phát hiện đơn flow |
| C. Suricata + DL sequence detector | Lợi ích của phát hiện hành vi nhiều flow |
| D. Suricata + ML + DL + Rule Generator | Hiệu quả phối hợp và luật được sinh |

Đo ở **đúng đơn vị**: flow-level cho ML, window/campaign-level cho DL, attack-scenario-level và benign traffic cho hệ thống luật. Báo cáo Recall, Precision, F1, FPR, cảnh báo/giờ, độ trễ, số luật hợp lệ, số luật bị từ chối và cải thiện so với baseline. Không so sánh hai Recall ở hai đơn vị khác nhau như một phép so sánh trực tiếp.

**Giả thuyết kiểm thử (không phải kết luận):** Cấu hình kết hợp phát hiện được ít nhất một kịch bản mà một trong hai nhánh riêng lẻ bỏ sót, trong khi FPR và độ trễ vẫn nằm trong mức chấp nhận được.

## 7. Ý nghĩa 'tấn công mới'

Đồ án thử nghiệm **hành vi/biến thể chưa thấy khi huấn luyện và/hoặc chưa được bộ luật cơ sở cảnh báo**, không khẳng định phát hiện mọi zero-day. Giữ kịch bản biến thể ngoài train, validation và quá trình chỉnh ngưỡng; dùng PCAP hoặc lưu lượng lab độc lập để kiểm chứng rule candidate. Phân biệt *unseen to model* với *missed by baseline rules*, vì hai khái niệm không đồng nhất.

## 8. Quy trình triển khai từng bước

1. **Phase 04:** data quality, đối chiếu feature Suricata, kiểm tra trường thời gian/host, thiết kế flow schema và sequence schema.
2. **Phase 05A:** ML Isolation Forest trên flow; baseline, ngưỡng và evaluation.
3. **Phase 05B:** tạo chuỗi từ CTU-13 phù hợp và dữ liệu Suricata lab; GRU Autoencoder, evaluation độc lập.
4. **Phase 05C:** correlation evidence, đánh giá bốn cấu hình A/B/C/D, ablation study.
5. **Phase 06:** rule templates, valid/test/review/deploy/rollback, dashboard và end-to-end evaluation.

**Trạng thái hiện tại:** Mới có hạ tầng VM1/VM3, dữ liệu và bước EDA ban đầu. Chưa chứng minh sự tương thích feature, chưa huấn luyện hai mô hình, chưa xây rule generator hoặc xác minh hiệu quả kết hợp.

## 9. Câu trả lời ngắn trước hội đồng

> Em chia mô hình thành hai mức phân tích. Machine Learning dùng Isolation Forest để sàng lọc bất thường trên **từng flow**, còn Deep Learning dùng mô hình chuỗi để nhận diện **hành vi bất thường tích lũy theo thời gian của một nguồn**. Hai nhánh phát ra hai loại bằng chứng khác nhau, được kết hợp trong bộ phân tích trước khi hệ thống sinh luật Suricata ứng viên. Luật phải được kiểm thử trên lưu lượng tấn công và bình thường độc lập, chứ không tự động áp dụng chỉ vì điểm ML hoặc DL cao. Em kiểm chứng tính bổ trợ bằng cách so sánh hệ thống chỉ ML, chỉ DL, phối hợp cả hai và bộ luật Suricata ban đầu.

## Nguồn kỹ thuật

- Suricata 8.0.3 — EVE JSON Format: https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-format.html
- Suricata 8.0.3 — Thresholding: https://docs.suricata.io/en/suricata-8.0.3/rules/thresholding.html
- scikit-learn — IsolationForest: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- CTU-13 structure (dataset overview): https://fkie-cad.github.io/COMIDDS/content/datasets/ctu_13/


Trong đồ án, em không triển khai Machine Learning và Deep Learning để giải quyết hai nhiệm vụ giống nhau. Em phân chia chúng theo cấp độ phân tích: Machine Learning phát hiện bất thường ở mức từng flow mạng, trong khi Deep Learning phân tích chuỗi hoạt động của một nguồn theo thời gian nhằm phát hiện các hành vi có tính liên tục hoặc phân tán qua nhiều flow.

Hai mô hình cung cấp bằng chứng bổ sung cho bộ phân tích hành vi. Từ những bằng chứng đủ tin cậy và có thể biểu diễn bằng cú pháp Suricata, hệ thống sinh luật ứng viên, kiểm thử và đánh giá trước khi áp dụng. Nhờ đó, mục tiêu nghiên cứu không chỉ là phát hiện bất thường mà còn là bổ sung khả năng phát hiện của Suricata đối với những hành vi hoặc biến thể chưa được bộ luật cơ sở nhận diện.