# Account Server

Dịch vụ Node.js/SQLite quản lý key, binding một UID, lease/heartbeat, lệnh khóa/force logout và trang admin responsive. Dịch vụ không lưu dữ liệu Zalo, proxy hoặc nội dung hội thoại. Runtime yêu cầu Node.js 22.13+ có `node:sqlite`; không có dependency npm hoặc native addon cần compile.

Production hiện tại: `https://103-253-23-106.sslip.io` (`/admin` cho quản trị, `/health` cho healthcheck).

## Chạy local

```powershell
node scripts/hash-password.js "mot-mat-khau-admin-rat-dai"
$env:ADMIN_PASSWORD_HASH="<hash-vua-tao>"
$env:KEY_ENCRYPTION_SECRET="<secret-ngau-nhien-it-nhat-32-ky-tu>"
$env:292VPN_PANEL_API_URL="https://panel.example.com"
$env:292VPN_PANEL_USERNAME="<xui-username>"
$env:292VPN_PANEL_PASSWORD="<xui-password>"
$env:DATABASE_PATH="./data/accounts.sqlite"
npm start
```

Local dùng HTTP để phát triển. Khi `NODE_ENV=production`, mọi endpoint ngoài `/health` chỉ chấp nhận TLS trực tiếp. Chỉ đặt `TRUST_PROXY=1` khi server nằm ngay sau reverse proxy do bạn kiểm soát; lúc đó `X-Forwarded-Proto: https` mới được tin cậy. Container chỉ bind `127.0.0.1:8080`; đặt Caddy/Nginx có HTTPS phía trước và không expose port này ra Internet.

## Docker/VPS

Tạo `server.env` cạnh `compose.yaml` (file đã nằm trong `.gitignore`) với tối thiểu:

```dotenv
ADMIN_PASSWORD_HASH=scrypt$...
KEY_ENCRYPTION_SECRET=<gia-tri-tu-openssl-rand-base64-32>
292VPN_PANEL_API_URL=https://panel.example.com
292VPN_PANEL_USERNAME=<xui-username>
292VPN_PANEL_PASSWORD=<xui-password>
```

Compose nạp file này bằng `env_file` ở chế độ `raw`, nên giữ nguyên ký tự `$` trong hash/secret và vẫn chuyển được các biến bắt đầu bằng chữ số như `292VPN_*`; không cần tạo thêm `.env`. Thêm các biến GPM, Proton hoặc WireGuard vào cùng `server.env`. Tạo secret riêng bằng `openssl rand -base64 32`, sau đó chạy:

```bash
# Chỉ cần tạo một lần trên VPS mới; volume này giữ SQLite và là external.
docker volume create zpm-account-data
docker compose up -d --build
docker compose config --quiet
```

Volume `account-data` giữ SQLite qua restart. Backup nhất quán bằng cách dừng container rồi sao lưu volume/database; không sao chép riêng file `.sqlite` khi WAL còn đang được ghi. Không đưa `server.env`, hash session, database, `KEY_ENCRYPTION_SECRET`, `292VPN_PANEL_API_TOKEN` hoặc key vừa sinh vào log/source control. `KEY_ENCRYPTION_SECRET` mã hóa full key trong SQLite bằng AES-256-GCM; mất hoặc thay secret sẽ khiến các key đã lưu không thể xem lại. Trang admin chỉ tải plaintext key khi quản trị viên bấm copy, qua endpoint yêu cầu session + CSRF và có audit.

Menu VLESS dùng X-UI Panel làm source of truth và yêu cầu `292VPN_PANEL_API_URL` cùng một trong hai cơ chế xác thực: `292VPN_PANEL_USERNAME` + `292VPN_PANEL_PASSWORD` (khuyến nghị, tự đăng nhập lại khi session hết hạn), hoặc `292VPN_PANEL_API_TOKEN` tĩnh. URL phải là HTTPS; chỉ đặt `292VPN_ALLOW_INSECURE_HTTP=1` cho môi trường local đáng tin cậy. Credential chỉ được gửi từ backend tới panel. URI VLESS không được lưu trong SQLite, HTML hoặc audit; nó chỉ xuất hiện trong response của thao tác tạo/sao chép đã có session và CSRF.

## Proton VPN

Proton account và rental được quản lý qua các route JSON `/admin/proton/*`. Tất cả route yêu cầu admin session; `POST`, `PUT`, `PATCH` và `DELETE` yêu cầu thêm CSRF qua body `csrf` hoặc header `X-CSRF-Token`. Cookie/password Proton được mã hóa bằng `KEY_ENCRYPTION_SECRET` và không xuất hiện trong projection, export hoặc audit.

- `PROTON_API_BASE_URL` mặc định là `https://account.protonvpn.com`, chỉ chấp nhận HTTPS.
- `PROTON_APP_VERSION` gửi trong header Proton; credential mặc định có thể để trống vì account được lưu trong database.
- `PROTON_AUTO_REVOKE=1` bật worker cleanup theo `PROTON_AUTO_REVOKE_INTERVAL_MS`; worker bỏ qua UID quản lý hiện tại.
- `GET /admin/proton/overview`, `/accounts`, `/accounts/:id/sessions`, `/export.json`, `/export.csv` là read-only.
- Tạo/sửa account dùng cookie, UID và tùy chọn password; assign rental dùng `PUT /admin/proton/rentals/:sessionUid` với `accountId`, `customer`, `phone`, `note`, `expiresAt` hoặc `duration` + `unit` (`hours`/`days`).
- Revoke chỉ xóa rental local sau khi Proton API thành công. Xóa Proton account bị từ chối nếu còn rental để tránh orphan dữ liệu.
- `POST /admin/proton/import` chỉ nhận JSON array hoặc `{ rentals, overwrite }`; mặc định không ghi đè rental đã có.
- Image Docker có sẵn helper Selenium tại `/app/scripts/refresh-proton.py`, Chromium và chromedriver. Compose mặc định chạy helper bằng `PROTON_REFRESH_COMMAND=/usr/bin/python3` cùng `PROTON_REFRESH_ARGS=["/app/scripts/refresh-proton.py"]`. Backend truyền JSON qua stdin gồm `id`, `email`, `uid`, `password`, `appVersion`; helper đăng nhập bằng Chrome headless ngay trên VPS, ưu tiên lấy cookie `AUTH-*` và fallback sang session `ps-*` trong localStorage, rồi trả JSON gồm `cookie`, `uid`, `appVersion`. Password lấy từ bản mã hóa trong SQLite, không đặt trên command line; cookie mới cũng được mã hóa trước khi lưu. `/tmp` của container được cấp 768 MB cho profile Chromium tạm và bị xóa sau mỗi lần chạy. Có thể override hai biến trên để dùng helper khác cùng contract.

## GPM Software

GPM dùng `GPM_EMAIL`/`GPM_PASSWORD`, tương thích `GPM_email`/`GPM_pass` khi chạy trực tiếp. Backend gọi `POST /auth/login`, giữ access token và refresh cookie trong memory, ưu tiên `GET /auth/refresh`; request 401/403 được retry một lần, không tự login khi upstream trả 429, 5xx hoặc JSON lỗi. `GPM_API_BASE_URL` chỉ dùng cho test và phải là HTTPS.

Các route admin gồm account, danh sách/chi tiết license, reset devices, tạo/xóa toàn bộ sub-license, schedule/extend/exchange sub-license và reveal key. Mọi route ghi yêu cầu admin session + CSRF. List/detail/audit chỉ trả projection đã mask; key đầy đủ chỉ có ở endpoint reveal. Schedule được lưu local theo UUID, không lưu full key; detail trả `scheduled`, `expiring`, `expired` hoặc `unscheduled` với cửa sổ `GPM_EXPIRING_WINDOW_HOURS` mặc định 72 giờ.

`GPM_AUTO_EXCHANGE=1` bật worker (mặc định bật) chạy mỗi `GPM_AUTO_EXCHANGE_INTERVAL_MS` (mặc định 60000 ms). Worker chỉ xử lý schedule đã đến hạn và `autoExchange=true`, xác minh sub-license vẫn thuộc parent, tuân thủ cooldown upstream 72 giờ từ `lastDevicesResetAt`, exchange rồi bắt đầu chu kỳ mới dài `termDays`. `GET /admin/gpm/worker` trả trạng thái an toàn của worker. Khi extend, backend cộng số ngày vào expiry hiện tại hoặc từ thời điểm hiện tại nếu đã hết hạn, đồng thời cộng vào `termDays`; do đó chu kỳ auto-exchange kế tiếp dùng tổng duration đã gia hạn.

### Lưu ý deploy qua Docker

- Khi chạy sau nginx trên cùng host qua Docker, nginx tới `127.0.0.1:8080` nhưng container thấy nguồn từ gateway bridge (VD `172.17.0.1`), không phải loopback. App tự đọc gateway mặc định từ `/proc/net/route` (`dockerGateway` trong `server.js`) và chỉ trust gateway đó khi `TRUST_PROXY=1`, nên không cần mở rộng thêm.
- Docker/entrypoint image `node` làm mất biến môi trường có tên bắt đầu bằng chữ số (VD `292VPN_PANEL_API_URL`) khi dùng `--env-file`. `compose.yaml` đã ghi đè entrypoint thành Node trực tiếp để PID 1 giữ các biến `292VPN_*`; thông tin đăng nhập 3x-ui/X-UI chỉ lấy từ env, không nhập trên giao diện hoặc lưu SQLite.

## Vận hành

- Khóa và force logout được lưu thành command theo generation, retry qua heartbeat/restart và chỉ ACK sau khi agent xác minh profiles đã dừng.
- Mỗi UID chỉ có một binding hiện hành. Khi UID kích hoạt key mới hợp lệ, server atomically archive key/account cũ, revoke session cũ, giữ binding cũ làm lịch sử và bind key mới.
- Reset binding revoke session và đánh dấu binding bằng `released_at`; account/key vẫn hoạt động để bind UID mới, còn UID cũ được giữ làm lịch sử. Key đã archive là tombstone vĩnh viễn: không restore, đổi hash, chuyển sang account khác hay xóa; SQLite trigger cũng chặn delete/key replacement ngoài các route admin.
- Khi nâng cấp database cũ, startup rebuild bảng `devices` nhưng giữ nguyên `devices.id` và FK `sessions.device_id`, sau đó kiểm tra `PRAGMA foreign_key_check`. Dừng container trước khi backup file SQLite/volume để có snapshot nhất quán.
- Mở khóa/gia hạn cập nhật entitlement; nếu session đã revoke, người dùng nhập lại key. API agent không trả key plaintext; chỉ admin đã xác thực mới có thể reveal key theo yêu cầu.
- Bootstrap admin bằng biến `ADMIN_PASSWORD_HASH`, tạo bằng `scripts/hash-password.js` (scrypt).

## Kiểm tra

```powershell
npm test
npm run check
```
