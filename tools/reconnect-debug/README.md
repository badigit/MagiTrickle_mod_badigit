# reconnect-debug — детерминированная локализация реконнектов «второй раз работает»

Общая оценка нод/каналов и приёмка BBR/pacing/shaper —
[net-diag в infra-docker](C:/Users/Dee/GitHub/infra-docker/tools/net-diag/WORKFLOW.md).
Этот каталог отвечает за роутерные улики и реконнекты; общий процесс ссылается сюда.

Harness для эпика **mt-ejz**. Цель — НЕ угадывать, а инструментально определить, на каком
слое рвётся первый коннект (а второй проходит): DNS-resolve / nftset-routing / mihomo-tunnel.

> Симптом (со слов): Claude Code и Telegram — первый запрос падает, со второго раза ок.
> Старт ~19–20 июня 2026, совпадает с коммитами после тега `0.5.2-badigit.14`. Но mihomo
> тоже обновлялся → без улик винить MagiTrickle нельзя.

## Карта слоёв и где рвётся

```
ПК ──SYN──> br0(LAN) ──> [MagiTrickle ipset → REDIRECT :5001] ──> mihomo redir/proxy ──> WAN(eth3) ──> upstream
        (syn-lan.pcap)      (conntrack reply sport=5001?)          (mihomo-poll.tsv)        (syn-wan.pcap)
```

Главный локализатор — **reply-tuple в conntrack** (роутер на legacy iptables; TCP-в-прокси
через `REDIRECT --to-ports 5001`, НЕ fwmark — все :443 потоки `mark=0`):
- reply `sport=5001` (reply src=<ROUTER_IP>) = поток **ПРОКСИРУЕТСЯ** (ушёл в mihomo redir);
- reply `sport=443` (reply src=реальный dst) = поток идёт **DIRECT** мимо прокси.

## Гипотезы (привязка к коммитам после .14)

| # | Слой | Коммит | Сигнатура в уликах | Чем ловим |
|---|------|--------|--------------------|-----------|
| **H1** | DNS-resolve | `c22cb2b` connPool race, `37ba6ba` recordsCache copies | resolved IP **отличается** между попыткой 1 и 2 | probe TSV (`connect_ip` разный) |
| **H2** | ipset population race | `17730a1` dnsResponseHook closure | тот же IP; 1й поток DIRECT (reply `sport=443`), 2й PROXIED (`sport=5001`) | conntrack reply-tuple + ipset.log тайминг |
| **H3** | routing disposition | `f326f4a` direct RETURN→ACCEPT | 1й SYN ушёл DIRECT на WAN непроксированным → RST/timeout | conntrack reply `sport=443` + syn-wan.pcap |
| **H4** | mihomo tunnel flap | НЕ MagiTrickle (апдейт mihomo) | оба потока PROXIED (`sport=5001`), но 1й UNREPLIED/быстрый DESTROY | mihomo-poll.tsv + mihomo-debug.log |

H1 vs (H2/H3) разделяет probe (DNS-уровень). H2/H3 vs H4 разделяет conntrack reply-tuple (sport 5001 vs 443).

## Быстрый старт (3 терминала, текущая HEAD-сборка = baseline)

**1. Залить и запустить захват на роутере** (read-only, ничего не меняет):
```bash
scp -O -P 222 tools/reconnect-debug/router-capture.sh root@<ROUTER_IP>:/opt/bin/
ssh -p 222 root@<ROUTER_IP> 'chmod +x /opt/bin/router-capture.sh && /opt/bin/router-capture.sh -d 300 -s <IP_ПК>'
# -s <IP_ПК> сильно режет шум (этот ПК = <CLIENT_IP>). Без -s ловит весь трафик.
# Опц. ipset-тайминг: добавь -I <setname> (имена: ssh <ROUTER_SSH> "ipset list -n | grep ^mt_").
```

**2. Параллельно — зонд с ПК** (PowerShell в корне репо):
```powershell
.\tools\reconnect-debug\local-probe.ps1 -For 300 -RouterHost root@<ROUTER_IP>
# -RouterHost вычисляет clock-offset ПК↔роутер (для корреляции). Таргеты правь -Targets.
```
В консоли жёлтые `RECONNECT` = пойманные события. Гоняй, пока не наберётся ≥10.

**3. Забрать улики и скоррелировать:**
```bash
scp -O -P 222 root@<ROUTER_IP>:/opt/var/log/reconnect-debug/<ts>.tar.gz .
tar -xzf <ts>.tar.gz
python3 tools/reconnect-debug/correlate.py probe-<ts>.tsv <ts>/conntrack.log --port 443
```
Вывод — таблица «таргет → класс (H1/H2-H3/H4)» + сводка. Это и есть вердикт по слою.

## Ручная классификация (если correlate не сматчил)

Для каждого жёлтого RECONNECT в probe-TSV возьми `connect_ip` провальной и успешной попытки:

1. **IP разный?** → **H1 (DNS)**. Смотри `c22cb2b`/`37ba6ba`.
2. IP тот же → найди в `conntrack.log` строки `[NEW] ... dst=<IP> dport=443`, смотри
   reply-tuple (второй `sport=` в строке):
   - 1й reply `sport=443` (DIRECT), 2й reply `sport=5001` (PROXIED) → **H2/H3 (ipset/route)**.
     Подтверждение H2: в `ipset.log` IP появился ПОСЛЕ времени 1го SYN.
     Подтверждение H3: в `syn-wan.pcap` 1й SYN ушёл на WAN, прилетел RST.
   - оба reply `sport=5001` (PROXIED), 1й `[UNREPLIED]`/быстрый `[DESTROY]` → **H4 (mihomo)**.
     Подтверждение: всплеск в `mihomo-poll.tsv` (alive/conn) или handshake-fail в `mihomo-debug.log`.

Проксируемый в conntrack: `... dst=<IP> dport=443 ... src=<ROUTER_IP> sport=5001 ...`.
Direct: `... dst=<IP> dport=443 ... src=<IP> sport=443 ...` (reply симметричен).

## A/B-эксперимент: откат на .14

Сделать **после** baseline на HEAD (методология: улики до изменения системы).

**Вариант A (предпочтительно) — поставить релизный ipk .14** (ровно то, что работало):
```bash
gh release download 0.5.2-badigit.14 --pattern '*aarch64*kn*.ipk' --dir .tmp/rollback
# залить и установить через штатный скрипт (он берёт ipk из пути):
powershell -File scripts/update-router-package.ps1 -PackagePath .tmp/rollback/<file>.ipk
```

**Вариант B — собрать из тега локально** (если релиза нет под рукой):
```bash
git worktree add ../mt-v14 0.5.2-badigit.14
# сборка ТОЛЬКО через WSL; из worktree пробрось PKG_VERSION (см. memory feedback_worktree_wsl_build):
#   PKG_VERSION=0.5.2 PKG_VERSION_PRERELEASE=badigit.14
# затем update-router-package.ps1 -PackagePath <собранный ipk>
```

**Прогнать ИДЕНТИЧНОЕ окно** (те же `-d`, те же таргеты, тот же `-s`):
```bash
ssh -p 222 root@<ROUTER_IP> '/opt/bin/router-capture.sh -d 300 -s <IP_ПК>'   # + local-probe.ps1
```
Сравнить долю `RECONNECT/FAIL` на HEAD vs .14. Резко упала на .14 → причина в коммитах
после .14 (H1/H2/H3). Не изменилась → причина вне MagiTrickle (H4, mihomo).

**Вернуть HEAD-сборку** после эксперимента:
```bash
powershell -File scripts/update-router-package.ps1   # берёт свежий собранный ipk HEAD
```

## Watchdog (always-on ловушка перемежающегося реконнекта)

Когда реконнект перемежающийся и в момент теста сети здоров — нужен непрерывный отлов.
`reconnect-watchdog.{sh,ps1}` крутятся сутками и фиксируют событие, когда оно случится.

**Запуск** (переживает закрытие Claude-сессии): ярлык `Desktop\start\start_mt-reconnect-watchdog.lnk`
или `tools\reconnect-debug\start-watchdog.cmd`. PC-скрипт сам заливает и поднимает роутерный демон.

- **Роутер** (`reconnect-watchdog.sh`, демон): `ct-YYYYMMDD-HH.log` — conntrack -E с почасовой
  ротацией (хранит 12ч), `mihomo-poll.tsv` (раз в 5с). Лёгкий, read-only.
- **ПК** (`reconnect-watchdog.ps1`): каждые 3с зондирует проксируемые таргеты; при ПЕРВОМ фейле —
  `[console]::beep`, запись в `bookmarks.tsv` и **снимок роутера** `event-<ts>-<tgt>-start.txt`
  (conntrack к падающему IP: `sport=5001`=проксируется→вина mihomo / `sport=443`=direct→вина MT).
  Файлы в `.tmp\reconnect-watchdog\`.

**Когда сработало** (есть `SPELL-START` в `bookmarks.tsv`): смотри `event-*.txt` (живое состояние в
момент T) и забери роутерный `ct-*.log` за тот час → `correlate.py` или ручная классификация по
reply-tuple. Длительность spell — между `SPELL-START` и `SPELL-END`.

**Грабли (выловлены, не повторять):**
- **dead-proxied ложняк (2026-07-16, вскрыт на mihomo-эпике):** conntrack на одиночный запоздалый
  сегмент (keepalive ~41Б/финальный ACK) после DESTROY здорового потока заводит loose-запись
  `[NEW]...ESTABLISHED [UNREPLIED]` и тут же убивает — DESTROY-сигнатура неотличима от мёртвого SYN.
  100% «Anthropic-стойлов» за 2026-07-16 были такими фантомами (у всех ASSURED-близнец на том же
  тапле). Детектор теперь требует SYN_SENT-рождение + отсутствие ASSURED-близнеца. При разборе
  строки dead-proxied.tsv всегда смотри ПОЛНЫЙ lifecycle тапла в ct-логе, не только DESTROY.
- PowerShell: `Select -Expand IPAddress` при ОДНОМ IP даёт скаляр-строку; функция ещё и разворачивает
  одноэлементный массив на возврате → `$ips[0]`='1'. Всегда `@(...)` на МЕСТЕ вызова.
- ssh из detached-процесса: `-o BatchMode=yes -o ConnectTimeout=10`, иначе вис на password-промпте без TTY.
- Не убивать процессы фильтром `CommandLine -like '*<имя-скрипта>*'` — команда матчит сама себя
  (исключай `$PID`).
- `pgrep -f <pat>` матчит сам checker (его cmdline содержит pat) → ложный «уже запущен». Bracket `[p]at`
  или `ps|grep '[p]at'`.

## Синтетика активных/idle потоков (добавлено 2026-07-17, mihomo-эпик)

Четыре зонда для локализации «где умирают соединения» (все параметризуются env):

- `synth-stall.sh` (роутер) — параллельные медленные HTTPS-потоки tunnel+direct
  ОДНОВРЕМЕННО (честный A/B в одном окне); сенсор `--speed-limit 1 --speed-time N`;
  `MODE=up` тестирует upload-направление (`__up`). Вердикты DONE/SURVIVED/STALL.
- `idle-hold.sh` (роутер) — голый TCP: жив ли конн после паузы T (нужен echo-сервер).
  Ограничение: цепочка режет нестандартные порты → таргет только 443/80.
- `tls-idle.sh` (роутер) — keep-alive паттерн Claude Code: GET → пауза T → GET#2 по
  тому же TLS-конну, tunnel vs direct. ⚠️ ГРАБЛЯ ИНТЕРПРЕТАЦИИ: socat НЕ различает
  server-FIN и тихую смерть (`dur==T` всегда — command substitution ждёт писателя,
  а не socat). Для FIN/RST/silence-вердикта — только python-зонды ниже.
- `exit-node-idle.py` (на выходном узле) / `pc-idle.py` (ПК) — python: тот же
  паттерн, но с прослушкой сокета всю паузу → точный вердикт ALIVE /
  FIN-DURING-IDLE / RST / SILENT-TIMEOUT. `pc-idle.py [T]` сам гоняет матрицу
  узлов: состав спрашивает у mihomo по группе из `MIHOMO_GROUP`, переключает по
  одному и в конце возвращает то, что было выбрано до прогона. Второй egress
  узла для `exit-node-idle.py` задаётся `EXIT_IFACE`.

**Факты, установленные этими зондами (2026-07-16/17, ночное окно):**
- Активные потоки (down И up) через туннель не умирают (25 мин, 0 стойлов) — даже
  сквозь вечерние волны RST-берстов реального трафика.
- api.anthropic.com edge закрывает idle keep-alive конны **FIN'ом ровно на ~400с**;
  idle до 390с переживается; FIN доносится до ПК через **все проверенные узлы** —
  и многохоповые, и одиночный хоп, независимо от транспорта. Ночью цепочка честная
  end-to-end.
- Оба «вечерних вердикта» (idle-killer, потеря FIN) НЕ подтвердились — открытым
  остаётся только механизм вечерних шторм-окон по Anthropic-коннам. Ловить: `pc-idle.py` + tcpdump В МОМЕНТ live-«retrying» у пользователя.
- Anthropic напрямую с локального IP → 403 (гео-блок), с зарубежного узла — 404,
  то есть 404 здесь признак «дошли», а не ошибки. Часть хостеров режет входящий
  локальный IP целиком, поэтому для direct-контроля годятся Cloudflare
  `__down`/`__up` и proof.ovh.net.

## Смежные инструменты (см. docs/router-debug-playbook.md)
- `router-snapshot` skill — точечный снимок (conntrack/listeners/configs).
- `tools/dns-bench` — нагрузочный DNS-тест + Δ inner-stats (leak).
- `curl :9090/connections/inner-stats` — мониторинг старого DoT-leak (артефакт #3, НЕ этот эпик).

## Грабли роутера
- BusyBox `sh`, нет python/bash. Анализ (correlate.py) — на ПК.
- `scp -O` обязателен (нет sftp-server). Только Windows OpenSSH (не git-bash ssh).
- conntrack/tcpdump/jq: `opkg install conntrack jq` (tcpdump обычно есть).
- WAN по умолчанию — iface default-маршрута (обычно `eth3`), LAN — `br0`.
