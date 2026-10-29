
# code by mobeiemi (duy phuc)
# Website Security Checker

Công cụ Python kiểm tra một số header bảo mật và minh họa cách phòng tránh SQL injection, XSS, command injection, path traversal bằng Python, JavaScript, PHP, Java và Go.

## Chạy

```powershell
python -m pip install requests
python security.py
```

Chỉ quét website bạn sở hữu hoặc được phép kiểm tra. Một số phép thử có gửi request chủ động; ưu tiên môi trường thử nghiệm.

Ví dụ secure coding nằm trong [`examples/secure_coding`](./examples/secure_coding). Chạy kiểm thử:

```powershell
python -m unittest discover -s tests -v
```
