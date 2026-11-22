# Runbook trình diễn IDS AI ba máy ảo

## Mục tiêu và giới hạn

Runbook này phục vụ hồ sơ **SHOWCASE_READY** khi các lệnh kiểm tra đạt yêu cầu. Nó không biến hồ sơ nghiên cứu thành **RESEARCH_ACCEPTED**. Model CTU tin cậy, khóa Hybrid production, dữ liệu holdout độc lập và capture mới vẫn là các cổng nghiên cứu riêng.

Luồng trình diễn:

```text
VM2 192.168.10.20  --traffic-->  VM1 192.168.10.10 Suricata 8.0.3
                                      | EVE read-only
                                      v
Windows relay  -->  VM3 192.168.10.30 shadow sink -> worker/review -> ELK
```

- VM1: cảm biến production hiện hữu; không sửa YAML, rules, EVE hay restart dịch vụ.
- VM2: chỉ tạo traffic nội bộ tới VM1.
- VM3: worker và dữ liệu showcase nằm trong `/home/tanhv/suricata-ai-showcase`.
- Hybrid production vẫn fail-closed. Khóa lab nếu được provision phải ghi rõ `LAB_DEMO_ONLY`.
- Không dùng lại cohort `fresh-holdouts-20261111` của SID9103012.

## Điều kiện trước khi chạy

Trên Windows cần:

- Git checkout đúng branch `feat/complete-suricata-ai-e2e`, worktree sạch.
- OpenSSH Agent đang chạy và ba Ed25519 identity đã được nạp.
- Host key đã có trong known_hosts.
- Ba alias `suricata-vm1`, `suricata-vm2`, `suricata-vm3` hoạt động với StrictHostKeyChecking.

Kiểm tra và mở ba terminal:

```powershell
.\scripts\demo\windows\Connect-ThreeVMs.ps1 -OpenTerminals
```

Triển khai đúng commit hiện tại vào thư mục user-owned trên cả ba VM:

```powershell
.\scripts\demo\windows\Start-Showcase.ps1
```

Lệnh này dùng `git archive`, lưu SHA commit và SHA archive trên từng VM, không ghi đè checkout cũ.

## Kiểm tra trạng thái

```powershell
.\scripts\demo\windows\Show-Status.ps1
```

Hoặc trong từng terminal:

```bash
# VM1
/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm1-status.sh
# VM2
/home/kali/suricata-ai-showcase/current/scripts/demo/vm2-status.sh
# VM3
/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-status.sh
```

## Khởi động EVE shadow relay

Relay chỉ đọc EVE production và ghi vào vùng shadow có giới hạn 128 MiB:

```powershell
.\scripts\demo\windows\Start-Eve-Relay.ps1
```

Lưu PID và log Windows do lệnh in ra. Không dùng `truncate`, `sed -i`, `rm` hoặc restart trên EVE production.

Relay giữ các record có newline hoàn chỉnh, rotate thành các file đánh số và
fail-closed khi tổng shadow storage đạt 512 MiB (`RELAY_STORAGE_CAP_REACHED`).
Relay hiện là best-effort: `tail -F -n 0` không có durable source cursor/ack,
vì vậy interruption có thể bỏ qua dữ liệu giữa các phiên; không gọi đây là
no-loss/no-duplicate delivery.

Quan sát EVE đã được khử thông tin nhạy cảm:

```bash
ssh suricata-vm1 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm1-show-eve.sh
ssh suricata-vm3 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-status.sh
```

## Normal và Attack traffic

Trước khi tạo traffic, khởi động HTTP service user-owned ở port unprivileged `18080`. Chỉ chạy trong mạng `192.168.10.0/24`.

Trên VM1:

```bash
ssh suricata-vm1 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm1-start-normal-service.sh 18080
```

Normal:

```bash
ssh suricata-vm2 /home/kali/suricata-ai-showcase/current/scripts/demo/vm2-generate-normal.sh
```

Lệnh chỉ thành công khi đủ 24 lần thử và có đúng 22 HTTP 200; nếu không, session bị từ chối là calibration evidence.

Attack thử nghiệm tốc độ thấp và capture Attack-only phải dùng workflow đã được
chuẩn bị, theo đúng thứ tự capture sẵn sàng rồi mới phát sinh traffic:

Trước khi chạy trên VM2, owner phải xác minh source đã deploy đúng commit đã
được review. Không chạy capture nếu checksum source không khớp; chỉ cập nhật
source trên VM2 sau khi owner phê duyệt riêng việc cập nhật:

```powershell
$ExpectedCommit = '<P1.1_REVIEWED_COMMIT_SHA>'
ssh suricata-vm2 "test `$(cat /home/kali/suricata-ai-showcase/runtime/source-commit.txt) = '$ExpectedCommit'"
# Sau owner approval riêng cho việc cập nhật source:
./scripts/demo/windows/Start-Showcase.ps1
```

Lệnh `Start-Showcase.ps1` chỉ là bước cập nhật source được owner phê duyệt;
không coi nó là authorization cho capture hoặc traffic.

```bash
ssh -tt suricata-vm2 /home/kali/suricata-ai-showcase/current/scripts/demo/vm2-capture-session.sh
```

Workflow này chỉ được owner chạy sau khi có phê duyệt riêng cho đúng VM2,
interface `eth1`, lệnh và phạm vi. PTY là bắt buộc để owner nhập mật khẩu qua
foreground `sudo -v`; sau đó tcpdump chạy non-interactive trong process group
được giám sát. Nó kiểm tra `192.168.10.20`, snaplen 96, tối đa 5.000 packet,
tối đa 120 giây, và BPF hai chiều giữa VM2/VM1 cho các port 18100–18123. Nó
chờ log `listening on eth1` trước khi gọi generator 24 probe unprivileged.
Timeout, lỗi, Ctrl-C hoặc generator failure đều dừng và reap tcpdump; không
dùng `setcap`, sudoers, firewall, tcpreplay hoặc capability fallback; không
overwrite evidence cũ. PCAP chỉ được rename và in `ATTACK_CAPTURE_READY` sau
khi verifier strict trả về `PASS`; lỗi vẫn giữ partial PCAP, log, metadata và
verification report.

Manifest generator không phải independent holdout và kết quả `24/24
rst_refused` không chứng minh PCAP đã bắt đủ packet. Dùng verifier offline sau
khi owner chuyển artifact:

```bash
python3 /home/kali/suricata-ai-showcase/current/scripts/verify_attack_evidence.py \
  --pcap /home/kali/suricata-ai-showcase/evidence/<attack>.pcap \
  --manifest /home/kali/suricata-ai-showcase/evidence/<attack>.json \
  --capture-metadata /home/kali/suricata-ai-showcase/evidence/<attack>.pcap.capture.json \
  [--eve /home/kali/suricata-ai-showcase/evidence/<eve>.jsonl]
```

PCAP Normal-only lịch sử `labcap-20261113T100057Z.pcap` (SHA256
`b0f9459ffa2280bad876302bba66f480d0c372a928d12e806cf6b3adaf54e528`) phải
được giữ nguyên và không được gắn nhãn Attack. Nếu EVE correlation chưa đủ,
ghi `PARTIAL` hoặc `BLOCKED`; không sửa EVE production hay ELK.

## ML và Hybrid

Worker flow-EVE yêu cầu artifact bốn feature đã được xác minh:

- `protocol_tcp`
- `duration_log`
- `packets_log`
- `bytes_log`

Khởi động worker:

```bash
ssh suricata-vm3 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-start-worker.sh
```

Nếu không có `metadata.json` và `pipeline.joblib` tương thích, lệnh phải trả về `ML_BLOCKED`. Không thay bằng model SYN năm feature và không gọi parse-only là ML inference.

Xem output nếu worker đã được provision artifact hợp lệ:

```bash
ssh suricata-vm3 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-show-inference.sh
```

Hybrid envelope chỉ được chấp nhận nếu public key lab đã được pin độc lập, payload ký đúng capture/run/sequence và replay/tampering bị từ chối. Không dùng key production hoặc approval cũ.

## Candidate và Suricata isolated

Không tạo hoặc kích hoạt candidate khi chưa có:

1. manifest mới với ít nhất 3 Attack và 3 Normal;
2. zero overlap với toàn bộ cohort SID9103012;
3. provenance model/calibration/capture đầy đủ;
4. safety evaluation độc lập, Normal false-positive bằng 0;
5. human approval candidate-specific.

Native Suricata offline replay là đường được ưu tiên:

```bash
ssh suricata-vm1 '/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm1-validate-candidate.sh <isolated-config> <isolated-rules> <pcap>'
```

Mọi đường dẫn phải nằm dưới `/home/tanhv/suricata-ai-showcase`. Rollback chỉ dừng runtime isolated do showcase tạo:

```bash
ssh suricata-vm1 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm1-isolated-rollback.sh
```

Không chạy các lệnh này với `/etc/suricata`, production rules, production PID hoặc production EVE.

Validator chỉ PASS khi config reference đúng canonical candidate rule file,
Suricata báo đã xử lý rule file và số rule loaded bao phủ các SID ứng viên.
Rollback chỉ PASS với evidence mới, bound vào candidate ID/SID, rule và PCAP
SHA256, run ID, post-rollback timestamp, zero candidate alerts và invariant
YAML/rules/PID production; offline evidence không được gọi là live rollback.

## Kibana và ELK

Kiểm tra read-only:

```bash
ssh suricata-vm3 /home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-show-dashboard.sh
```

Từ Windows, mở local forward tường minh rồi truy cập `http://127.0.0.1:5601/app/discover`:

```powershell
ssh -N -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -L 5601:127.0.0.1:5601 suricata-vm3
```

Index showcase là `suricata-ai-showcase-*`. Không ghi vào các index lịch sử.

## Dừng an toàn

```powershell
.\scripts\demo\windows\Stop-Showcase.ps1
```

`Stop-Showcase.ps1` dừng relay Windows theo PID file đã ghi bởi `Start-Eve-Relay.ps1`. Kiểm tra lại:

```powershell
.\scripts\demo\windows\Show-Status.ps1
```

Production Suricata/Filebeat phải còn cùng PID và cùng checksum trước/sau.

## Sự cố thường gặp

- SSH lỗi: kiểm tra `Get-Service ssh-agent`, `ssh-add -l`, sau đó chạy lại `Connect-ThreeVMs.ps1`; không tắt host-key checking.
- `ML_BLOCKED`: thiếu artifact flow bốn feature đã xác minh; đây là blocker trung thực.
- `CAPTURE_BLOCKED`: thiếu capability capture; xin owner phê duyệt đúng phương thức capture, không dùng sudo.
- Không có EVE mới: kiểm tra relay log Windows và chỉ đọc trạng thái Suricata/Filebeat trên VM1.
- Candidate bị từ chối: giữ nguyên artifact và ghi `REJECTED`; không retune trên holdout.
- Không dùng cohort `fresh-holdouts-20261111` cho thí nghiệm mới.

## Trạng thái nghiên cứu hiện tại

- EVE parse-only và EVE-to-ELK transport đã có bằng chứng hash-linked.
- CTU production model: BLOCKED.
- Hybrid production trust: BLOCKED.
- Independent new cohort: ACCEPTED for bounded showcase demo; not a production/zero-day claim.
- Candidate activation/rollback: BLOCKED.
- T0–T11 đầy đủ: NOT_MEASURED.

## Packet evidence và các cổng nghiên cứu còn lại

Evidence đã freeze được ghi trong
`docs/final-showcase-packet-evidence-2026-11-13.md`. VM2 có `eth1`, nhưng
`getcap /usr/bin/tcpdump` không có `cap_net_raw`; wrapper trả về
`CAPTURE_BLOCKED` và exit 77. Không tự ý chạy sudo hoặc thay đổi capability.
Owner chỉ chạy workflow mới sau khi xác minh source commit đã deploy trên VM2
khớp với commit đã review và sau khi có phê duyệt riêng cho phương thức
capture. Không dùng lệnh SSH cũ bên dưới và không cập nhật VM2 tự động:

```bash
ssh suricata-vm2 "test \$(cat /home/kali/suricata-ai-showcase/runtime/source-commit.txt) = '<P1.1_REVIEWED_COMMIT_SHA>'"
ssh -tt suricata-vm2 /home/kali/suricata-ai-showcase/current/scripts/demo/vm2-capture-session.sh /home/kali/suricata-ai-showcase/evidence/<RUN_ID>.pcap
```

Lệnh kiểm tra commit phải thành công trước khi gọi capture; nếu source không
khớp thì dừng và owner mới quyết định riêng việc cập nhật bằng
`Start-Showcase.ps1`. Không có PCAP mới thì không provision producer key `LAB_DEMO_ONLY`, không ký
packet evidence, không tạo candidate mới và không gọi isolated replay/rollback
là thành công. SID9103012 giữ nguyên trạng thái REJECTED.

## Showcase EVE-native đã được chấp nhận ở mức demo (2026-11-13)

Artifact `showcase_demo` dùng đúng bốn feature EVE: `protocol_tcp`,
`duration_log`, `packets_log`, `bytes_log`. Model chỉ được huấn luyện trên
development; threshold chỉ được chọn trên calibration. Các attempt Normal
`rst_refused` là `negative_control`, có `label=null` và bị loại khỏi mọi metric
nhị phân; chỉ HTTP 200 là Normal nhị phân.

Cohort độc lập mới gồm 3 Attack và 3 Normal: mỗi Attack 24/24 RST, mỗi Normal
22 HTTP 200 và 2 RST control. Correlation yêu cầu đúng five-tuple, flow ID,
event hash và bounded flow timestamps. Split overlap theo session, attempt hoặc
canonical EVE event hash đều bị từ chối trước khi fit.

Kết quả holdout độc lập ở mức flow: TP=72, FN=0, FP=0, TN=66; precision=1.0,
recall=1.0, F1=1.0, FPR=0.0. Ở mức session: Attack detection rate=3/3,
Normal false-alert rate=0/3. Đây là cohort demo được kiểm soát, không phải
bằng chứng zero-day hoặc production model.

Index thực tế là `suricata-ai-showcase-2026.11.13`; 607 documents đều có
profile, demo-only, model/data/calibration lineage, các cờ approved/deployable/
deployed=false và `REVIEW_ONLY`. Dashboard showcase không ghi vào production
ELK/Filebeat; mở bằng SSH local forwarding `-L 5601:127.0.0.1:5601`.

Vì vậy runbook này là khung showcase an toàn và fail-closed; chỉ gọi là `SHOWCASE_READY` sau khi chạy thực tế các bước tương ứng, không gọi là `RESEARCH_ACCEPTED`.

