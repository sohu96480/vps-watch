# VPS Watch

Debian / Ubuntu **systemd 主机**的只通知监控，Python ≥3.9、仅标准库；支持 amd64 / arm64。独立使用 `/opt/vps-watch`、`/etc/vps-watch`、`/var/lib/vps-watch`，不修改原 `baisi-watch`。无自动更新、无 Telegram 命令轮询（不调用 `getUpdates`），可与其他使用同一机器人的应用共用收件聊天。

**不支持 OpenWrt、Alpine、非 systemd 系统及普通 Docker 容器。不会安装 Docker。监控不是杀毒软件，不证明整台主机安全，也不会杀进程、封 IP、重启业务或修复文件。曾被入侵的机器应独立调查，必要时重装并轮换密钥。**

## 安装 / 手动更新

以 root 执行，先下载再执行，下载失败不会运行旧脚本：

```bash
curl --fail --show-error --location --retry 3 --connect-timeout 10 --max-time 60 \
  https://raw.githubusercontent.com/sohu96480/vps-watch/main/install.sh \
  -o /root/vps-watch-install.sh && bash /root/vps-watch-install.sh
```

上面是可审阅的安装器入口；安装器随后经 GitHub API 解析 `main` 的 40 位 commit SHA，并下载**固定 SHA** 源码归档。HTTPS/GitHub 账号信任仍是前提；这不是离线签名校验。完整本地仓库安装：`bash ./install.sh`（使用当前本地文件，不联网取新版本）。可先审阅源码再运行。

仅在缺少依赖时通过 apt 安装 `python3 ca-certificates curl`，需要 root 和可用的 apt 源。已有 Python 低于 3.9 会清楚退出，不自动跨发行版升级。初次安装通过 `/dev/tty` 输入主机标签、隐藏输入的 Telegram bot token 与数字 chat ID。请先向自己的 bot 发消息/将其加入目标群并赋予发送权限。

已有根用户私有 JSON 可导入，同一 bot 与 chat 可复用，不需要另建 bot：

```bash
chmod 600 /root/my-private-watch.json
bash /root/vps-watch-install.sh --config /root/my-private-watch.json --name '我的主机'
```

JSON 字段：`token`、`chat_id`，可选 `name`、`services`（服务名数组）、`containers`（容器名数组）。**不要将此文件放进仓库，不要把实际 token 写进命令行、工单或截图。** 导入文件须 root 所有、不能授予组/其他用户权限。私有配置仅保存在 `/etc/vps-watch/config.json`，权限 600，目录 700。

重复运行相同安装命令即手动更新。已有凭据、主机名、监控目标、状态和旧基线保留；`--name` 是显式修改名字。已有安装忽略 `--config`，避免更新时无意替换凭据；如需修改，root 编辑本地配置并重启服务。运行中的 `baisi-watch.service` 会让安装中止，先自行安排迁移，避免双重通知。

## 目标发现与更新

初次安装自动发现当前 systemd `running` 的非 oneshot 长期服务（排除自身和原监控），以及 `docker ps` 中正在运行的容器；不安装 Docker。发现当下不代表业务重要性：请审阅输出/配置，短暂服务未来退出也可能被监控。未运行的服务不会自动加入，后来新增目标也不会在更新时自动加入。

```bash
# 明确重新发现：保留原目标，只追加新目标
bash /root/vps-watch-install.sh --rediscover
# 先查看现有配置/发现结果；明确愿意替换时才使用下面的危险选项
bash /root/vps-watch-install.sh --rediscover --replace-targets --confirm-replace-targets
```

## 告警、恢复与完整性

- 每轮目标 10 秒（大量服务、磁盘扫描、网络超时会延长实际周期）。CPU 连续三个区间采样 ≥90%，内存/根文件系统占用 ≥90%，被监控服务非 active、容器非 running 触发告警。首次 CPU 仅建立计数器；重启后继续保存的采样状态。
- 固定已知可疑进程名/路径特征匹配，仅提示复核，可能误报/漏报，不做恶意归因和自动清除。
- 记录 systemd、cron、SSH、sudo、passwd/shadow/group、启动文件、自身代码及配置的 SHA-256、元数据或软链接目标。通知**仅路径，不发送文件内容或哈希**；递归覆盖 `/root/.ssh`，不是所有用户的家目录。高频大文件目录会增加开销。非 root 攻击/全部恶意行为不一定可见。
- 新异常及恢复首先写入 root-only 持久队列；发送失败按退避 10 秒起、最高 300 秒重试，每 900 秒仍异常再次排队提醒。队列 FIFO 保证先告警后恢复，网络恢复可能先收到已过时告警再收到恢复。Telegram `ok=true` 且返回的 `chat.id` 与配置完全一致才算成功。进程在 Telegram 已送达、但尚未落盘确认时崩溃，重试可能重复投递（至少一次语义，不承诺恰好一次）。长期离线会积压，需监测磁盘。
- SSH 每约 30 秒读取 journal，以 `_COMM=sshd` 和 `_COMM=sshd-session` 同字段 OR 匹配；不依赖 unit 名，不用 `--grep`。所有匹配日志推进 cursor，成功/失败数量聚合，附原事件时间范围（UTC），不发送原始日志用户名/内容。首次从当前尾部开始，不回放历史；空 journal 保留起始时间。journal 被清理/游标不可用会报告检查错误，不静默跳过。自定义 sshd COMM、非 journal SSH 日志不在覆盖范围。

**基线只在服务 enable 后首次创建，更新永不自动刷新。代码更新本身也应触发完整性变化，需人工检查。记录基线不是“系统已清白”的认证。**

```bash
# 查看本地健康信息和服务；健康 ok 不代表所有监控目标无异常
systemctl status vps-watch --no-pager
journalctl -u vps-watch -n 50 --no-pager
python3 -m json.tool /var/lib/vps-watch/health.json
# 审核确认后才接受新基线；旧基线另存到状态目录
systemctl stop vps-watch
python3 -B /opt/vps-watch/watch.py --accept-baseline --confirm
systemctl start vps-watch
```

`--init` 遇到已有基线会拒绝。缺失/损坏基线不会静默重建；请调查并在服务 enable 后明确初始化。状态文件可能含内部路径，不要公开上传。

## 通知验证与无害演练

安装器检查服务多个周期：MainPID / NRestarts 稳定、health.json 的成功检查时间前进，然后做**真实** Telegram 发送与目标 chat 校验。服务启动不正常会回滚代码/单元/配置；Telegram 失败则退出码 2，保留本地安装，明确 **未验证通知**，不假装安装完整成功。

```bash
# 仅测试实际发送，不需要停服务（不会占用 getUpdates）
python3 -B /opt/vps-watch/watch.py --test
# 完整定时检测->告警->恢复，不停业务、不破坏系统
install -m 600 /dev/null /etc/vps-watch/test.flag
# 等待至少一轮并检查 Telegram 与 health.json 的 exercise
rm /etc/vps-watch/test.flag
# 再等一轮确认恢复

# 一轮检查 / 队列演练需要停监控，避免同时改状态
systemctl stop vps-watch
python3 -B /opt/vps-watch/watch.py --once
python3 -B /opt/vps-watch/watch.py --exercise
systemctl start vps-watch
```

`--exercise` 使用持久发送队列；失败不会丢演练信息。`--once` 检查成功返回 0，检查错误返回 1；通知待发送数请查看 health.json（检查成功与消息送达分开）。

## 备份与回滚

更新前停自己的服务，并在 `/var/backups/vps-watch/时间-随机串/`（700）备份旧代码、单元、配置、状态。保留备份便于人工审查；其中含 token，**不可发布**。启动失败自动还原代码、单元、配置并尝试重启旧版本，不回滚运行状态以免丢队列/cursor。首次失败的诊断状态保留，首次 enable 会撤销。软件包安装和手动输入不属于应用文件事务；不会回滚 apt。

本地 root 能修改程序、基线、日志和凭据；本机断电/失联也不能向外通知。需要外部监控才能发现主机失联。权限依赖 root 读取安全文件/日志及 Docker socket；systemd 沙箱限制写入状态目录，仍不能把此程序视为抵御 root 攻击的安全边界。

## 本地验证（不部署到生产）

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
systemd-analyze verify vps-watch.service
```

`VPS_WATCH_ROOT=/某个隔离目录 bash install.sh --dry-run` 支持模拟 os-release/systemd 目录并验证无写入。完整带前缀的真实安装**明确拒绝**，防止意外操作宿主 systemd。测试使用临时 root、假 journalctl/命令接口、真实 Python 子进程，验证重试/恢复、基线保留、事务失败回滚、发现过滤、SSH 解析及空日志、health.json。未做真实 Telegram 或真实新装 systemd VPS 验收时，不应据此声称生产已验证。
