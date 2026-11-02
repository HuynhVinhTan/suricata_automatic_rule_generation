Research Finding — CIC-IDS2017

Phát hiện: CIC-IDS2017 sử dụng duration theo microsecond, các giá trị tốc độ có thể rất lớn khi flow ngắn, và file CSV hiện tại có hai cột cùng tên Fwd Header Length.

Quyết định: Chuyển đơn vị duration về giây trong adapter; chưa tự động loại cột trùng hoặc gộp dữ liệu với UNSW-NB15.

Bằng chứng: Kiểm tra trực tiếp header 79 cột, kiểu dữ liệu và xác minh công thức packet/byte rate trên mẫu thực tế.

Chưa hoàn thành: Kiểm chứng thống kê packet/byte theo chiều và đánh giá toàn bộ chất lượng dữ liệu CIC.