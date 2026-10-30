# Phạm vi nghiên cứu, định nghĩa “tấn công mới” và chiến lược thực nghiệm

> Tài liệu đề xuất cho README/đồ án — 26/10/2026. Đây là \*\*phạm vi và kế hoạch nghiên cứu\*\*, chưa phải kết quả đã kiểm nghiệm.

## 1\. Tên đề tài đã đăng ký

**Sinh tự động luật Suricata dựa trên mô hình học máy phát hiện tấn công mới**

Mục tiêu không dừng ở mô hình phân loại Normal/Attack. Hệ thống dự kiến phát hiện hành vi mạng bất thường bằng ML/DL, rút ra những điều kiện quan sát được và **sinh luật Suricata dạng ứng viên** từ các mẫu/template được kiểm soát. Mỗi luật phải được xác minh cú pháp, thử nghiệm với lưu lượng bình thường và tấn công, đối chiếu bộ luật Suricata ban đầu, rồi mới được xem xét đưa vào vận hành. Không mặc định triển khai tự động mọi luật vừa sinh.

## 2\. “Tấn công mới” được hiểu thế nào?

1. **Mới đối với bộ luật đang sử dụng** (*rule-set novelty*): hành vi/mẫu biến thể chưa được bộ luật cơ sở cảnh báo trong điều kiện thí nghiệm, nhưng hệ thống phân tích bất thường nhận diện và đưa ra luật ứng viên. Đây là mục tiêu triển khai chính, **phải chứng minh qua phép so sánh baseline**.
2. **Mới đối với dữ liệu huấn luyện** (*unseen-behavior / held-out novelty*): một nhóm/biến thể được giữ hoàn toàn ngoài tập huấn luyện và chọn ngưỡng; đánh giá sau cùng xem mô hình có phát hiện được hành vi bị giữ lại hay không. Đây là phép thử bổ sung để đánh giá khả năng khái quát hóa.
3. **Zero-day theo nghĩa lỗ hổng chưa từng biết**: đề tài **không tuyên bố** chắc chắn phát hiện được mọi zero-day, xác định CVE mới, hay tự sinh được signature của mọi kỹ thuật khai thác. Kết quả anomaly detection chỉ cho thấy khác biệt so với phân phối dữ liệu tham chiếu, không tự nó chứng minh sự tồn tại của một cuộc tấn công.

Vì vậy, **việc xác định một số kịch bản tấn công để kiểm thử không mâu thuẫn với mục tiêu phát hiện tấn công mới**. Kịch bản đã biết được dùng để huấn luyện/đánh giá có kiểm soát; “mới” phải được xác lập bằng sự vắng mặt trong luật cơ sở hoặc trong tập huấn luyện (tuỳ từng thí nghiệm), chứ không phải chỉ gắn nhãn “mới”.

## 3\. Phạm vi ưu tiên

|Mức độ|Nhóm hành vi|Dữ liệu/bối cảnh đang có|Vai trò và lý do|Giới hạn|
|-|-|-|-|-|
|**Chính**|**Port Scanning / Reconnaissance**|UNSW-NB15 có nhãn `Reconnaissance`; kiểm thử bổ sung trên mạng lab VM2→VM1|Biểu hiện có thể quan sát ở lưu lượng TCP/UDP: tần suất thăm dò, trạng thái kết nối, số đích/cổng trong cửa sổ thời gian; thuận tiện kiểm tra việc sinh luật ứng viên|`Reconnaissance` rộng hơn `Port Scanning`; nhãn UNSW không chứng minh từng dòng là scan. Cần gán nhãn riêng các kịch bản lab|
|**Mở rộng, có điều kiện**|**DoS / DDoS**|UNSW-NB15 có `DoS`; file CIC-IDS2017 hiện có là **Friday Afternoon DDoS**, không phải file PortScan|Kiểm thử hành vi tăng đột biến lưu lượng và khả năng khái quát hoá ngoài scan|DDoS phân tán cần nhiều nguồn/tổng hợp theo đích; rule packet-level đơn giản có thể không biểu diễn đầy đủ|
|**Khảo sát/đánh giá bổ sung**|**Botnet/C2-related flows**|Một capture `.binetflow` thuộc CTU-13|Kiểm tra khác biệt dữ liệu, nguy cơ domain shift và giới hạn bộ feature|Chưa cam kết sinh luật cho Botnet từ một file CTU-13|
|**Ngoài phạm vi cam kết chính**|Exploits, Shellcode, Worms, Backdoors, SQLi, XSS...|Một số chỉ có nhãn tổng quát hoặc chưa có bộ dữ liệu phù hợp|Có thể xuất hiện trong EDA và thí nghiệm so sánh|Không tuyên bố hệ thống sinh được luật có chất lượng cho tất cả loại này|

**Quyết định:** một kịch bản chính có thực nghiệm đầy đủ tốt hơn liệt kê nhiều loại tấn công nhưng không tạo và đánh giá được luật Suricata. Mở rộng sang DoS/DDoS **chỉ khi** chứng minh được feature có trong thực tế và rule template biểu diễn được hành vi được chọn.

## 4\. Kiến trúc nghiên cứu cần hoàn thiện

### Offline: nghiên cứu, huấn luyện và tạo luật ứng viên

1. Kiểm tra chất lượng dữ liệu, mô tả ngữ nghĩa nhãn, đo phân phối lớp.
2. Xác minh các đặc trưng có thể tái tạo từ Suricata EVE hoặc bộ tổng hợp flow/window của hệ thống. **Không xem các field trùng tên là tự động tương đương**.
3. Tách train/validation/test nhằm tránh trùng bản ghi, trùng phiên/nguồn và lộ thông tin giữa tập, tùy điều kiện dữ liệu.
4. Mô hình cốt lõi: **Isolation Forest (ML)** và **Deep Autoencoder (DL)** học hành vi bình thường để chấm điểm bất thường; mô hình phân loại có giám sát (nếu có) chỉ dùng làm baseline so sánh. Ngưỡng chỉ được chọn trên validation.
5. Liên kết các bất thường với **điều kiện mạng có thể giải thích** (ví dụ: mẫu SYN lặp trong cửa sổ, chiều lưu lượng, tần suất theo IP). Không chuyển trực tiếp score liên tục của mô hình thành điều kiện Suricata khi engine không hỗ trợ.
6. Sinh rule ứng viên từ template theo đúng cú pháp Suricata và ghi metadata: nguồn phát hiện, giá trị ngưỡng, SID, `rev`, ngày, chứng cứ, giới hạn và phiên bản.
7. Kiểm tra cú pháp (`suricata -T` trên cấu hình thử nghiệm) và replay thử nghiệm; so với rule baseline bằng Precision, Recall/Detection Rate, False Positive Rate, số cảnh báo sai trên lưu lượng bình thường và tác động hiệu năng.

### Online: vận hành sau khi kiểm thử

Suricata VM1 → Filebeat → Logstash/Elasticsearch VM3 → feature adapter + aggregation → mô hình đã lưu + preprocessor + schema → anomaly/event candidate → rule candidate → kiểm duyệt/kiểm thử → có thể bổ sung vào Suricata. Luật chưa qua kiểm thử **không được kích hoạt trên hệ thống thật**.

**Giới hạn kỹ thuật cụ thể:** Suricata **8.0.3** hỗ trợ `threshold`/`detection\_filter` để đếm **số lần khớp**, không nên diễn giải là tự đếm “số cổng đích khác nhau”. Nếu tiêu chí scan cần số cổng khác nhau theo IP và cửa sổ thời gian, phải tính ở tầng aggregation; mẫu rule được sinh phải biểu diễn đúng điều kiện mà Suricata hỗ trợ, nếu không phải báo giới hạn và không sinh luật sai ngữ nghĩa.

## 5\. Thiết kế kiểm thử “mới” và thành công

* **A. Known/standard evaluation:** trên test dữ liệu độc lập; đánh giá anomaly score và baseline có giám sát (nếu dùng). Không coi kết quả này là bằng chứng phát hiện attack chưa biết.
* **B. Held-out behavior:** chọn trước một nhóm/biến thể, giữ khỏi train *và* khâu chọn ngưỡng. Xem recall trên nhóm bị giữ lại và false alarm trên traffic bình thường; tránh cho dữ liệu held-out ảnh hưởng lựa chọn tham số.
* **C. Baseline vs candidate rules:** ghi lại phiên bản bộ luật cơ sở, tập traffic kiểm thử và trường hợp chưa bị baseline cảnh báo. Chạy bộ luật cơ sở và bộ luật có candidate trong cùng điều kiện; đo tăng trưởng phát hiện và cảnh báo sai.
* **D. End-to-end:** kiểm chứng rule sinh ra đã thực sự hợp lệ, có thể nạp và sinh cảnh báo đúng trong Suricata 8.0.3 (không chỉ dừng ở file `.rules`). Đo độ trễ/cost nếu có điều kiện.

Nếu chỉ chứng minh được A mà chưa làm B/C/D, **không được kết luận đề tài đã đạt mục tiêu sinh luật cho tấn công mới**.

## 6\. Những điều đã xác minh và những việc chưa làm

**Đã xác minh:** hạ tầng Suricata 8.0.3 + Filebeat trên VM1, Docker ELK trên VM3 hoạt động ở mức cấu hình/service; export cấu hình khớp SHA256; repository đã chuẩn hóa; có UNSW-NB15 training/testing, CIC-IDS2017 Friday DDoS, một file CTU-13; UNSW Training có tỷ lệ `label=1` \~68,06% và `label=0` \~31,94%.

**Chưa có kết quả xác nhận:** accuracy/recall/FPR của bất kỳ mô hình nào, detection held-out, kết quả sinh rule hợp lệ, hiệu quả so với bộ luật cơ sở, tính tương thích feature đầy đủ. Dữ liệu lệch nhãn mạnh nên **không** được huấn luyện Autoencoder mô hình bình thường trên toàn bộ UNSW training mà không lọc/tách normal.

## 7\. Câu trả lời ngắn khi bảo vệ

> Đề tài của em là sinh tự động luật Suricata dựa trên học máy để hỗ trợ phát hiện những hành vi tấn công mới đối với tập luật hiện hành, chứ không tuyên bố phát hiện được mọi lỗ hổng zero-day. Em chọn Port Scanning/Reconnaissance làm kịch bản chính vì hành vi có các dấu hiệu lưu lượng có thể đo và diễn đạt bằng điều kiện giám sát, nên đánh giá được toàn bộ chu trình từ phát hiện bất thường đến sinh và kiểm thử luật. DoS/DDoS được xem xét như kịch bản mở rộng nếu có đủ đặc trưng và rule template phù hợp. Em sử dụng Isolation Forest và Deep Autoencoder để học mẫu lưu lượng bình thường, đánh giá riêng các hành vi chưa xuất hiện khi huấn luyện, rồi so sánh bộ luật Suricata ban đầu với các luật ứng viên đã qua kiểm thử. Chỉ khi có bằng chứng phát hiện thêm mà vẫn kiểm soát được cảnh báo sai thì em mới kết luận luật sinh ra có giá trị.

## 8\. Nguồn tham khảo chính

* [UNSW-NB15 dataset — University of New South Wales](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
* [CIC-IDS2017 — Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
* [CTU-13 — Stratosphere Laboratory](https://www.stratosphereips.org/datasets-ctu13)
* [Suricata 8.0.3 — Rules Format](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
* [Suricata 8.0.3 — Thresholding](https://docs.suricata.io/en/suricata-8.0.3/rules/thresholding.html)
* [Scikit-learn — Novelty and Outlier Detection](https://scikit-learn.org/stable/modules/outlier_detection.html)


Chọn Port Scanning vì đề tài chỉ phát hiện được Port Scanning. Em chọn nó làm kịch bản chính để chứng minh toàn bộ quy trình: học hành vi bình thường, phát hiện bất thường chưa được luật cơ sở cảnh báo, sinh luật Suricata và đánh giá luật mới. Sau khi chứng minh quy trình trên một loại hành vi cụ thể, em mới mở rộng sang những nhóm tấn công khác.


Ban đầu, Suricata sử dụng bộ luật đã biết. Khi xuất hiện hành vi mạng bất thường mà bộ luật hiện tại chưa phát hiện, ML và DL phân tích để cung cấp bằng chứng về nguy cơ tấn công. Nếu hệ thống xác định được một mẫu hành vi đáng tin cậy và có thể biểu diễn bằng luật Suricata, nó sẽ tự động sinh luật ứng viên, kiểm thử và đề xuất triển khai. Sau khi luật được kích hoạt, Suricata có thể nhận diện những lần xuất hiện tương tự trong tương lai.