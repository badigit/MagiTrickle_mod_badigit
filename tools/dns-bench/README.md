# dns-bench

Нагрузочный тест DNS-стека MagiTrickle/mihomo. Гонит A-запросы на роутер, считает rps/latency/errors. Параллельно показывает дельту `inner-stats.alive` mihomo — индикатор утечки трекера под нагрузкой.

## Содержимое

```
tools/dns-bench/
  main.go              # Go-бенч (miekg/dns), компилится в dns-bench[.exe]
  go.mod / go.sum      # отдельный модуль magitrickle.local/dns-bench
  run.sh               # runner с тремя сценариями + замер inner-stats
  dns-bench.exe        # собранный бинарь (Windows amd64)
  data/
    in-group.txt       # 50 доменов, попадающих в группы MagiTrickle (через прокси)
    out-of-group.txt   # 46 доменов вне групп (DIRECT-роутинг)
    mix.txt            # 92 домена 50/50 — реалистичный сценарий
```

## Сборка

```bash
wsl -e bash -c '
  export GOROOT=$HOME/sdk/go1.23.0
  export PATH=$GOROOT/bin:$PATH
  cd /mnt/c/Users/Dee/GitHub/MagiTrickle/tools/dns-bench
  GOOS=windows GOARCH=amd64 go build -o dns-bench.exe .
'
```

Под Linux: `go build -o dns-bench .` (без `GOOS`).

## Использование

### Через runner (рекомендуется)

```bash
cd tools/dns-bench
./run.sh <scenario> <rps> <duration>
```

| `scenario` | что прогоняет |
|---|---|
| `in-group` | домены из правил MagiTrickle (через прокси-цепочку) |
| `out-of-group` | домены DIRECT (минуют прокси) |
| `mix` | смесь 50/50 |
| `all` | все три по очереди с паузами 5с |

Примеры:
```bash
./run.sh out-of-group 50 15s   # smoke
./run.sh mix 100 30s           # обычная нагрузка
./run.sh all 100 30s           # полный профиль
./run.sh in-group 500 60s      # стресс
```

Переменные окружения (опционально):
- `SERVER` — DNS-сервер (default `10.9.0.1:53`)
- `RAPI` — mihomo external-controller (default `http://10.9.0.1:9090`)

### Прямой вызов бинаря

```bash
./dns-bench.exe \
  -server 10.9.0.1:53 \
  -domains data/mix.txt \
  -rps 100 \
  -duration 30s \
  -concurrency 32 \
  -timeout 5s \
  -progress 5s
```

Флаги:
- `-server host:port` — целевой DNS-сервер
- `-domains <file>` — список доменов (по одному на строку, `#` — комментарий)
- `-rps int` — целевая частота
- `-duration` — длительность (`30s`, `5m`)
- `-concurrency` — число воркеров (default 16)
- `-timeout` — таймаут одного запроса (default 5s)
- `-tcp` — TCP вместо UDP
- `-progress` — интервал прогресс-репорта (0 = выключить)

## Интерпретация результатов

### Что считается успехом

| Метрика | Норма | Тревога |
|---|---|---|
| `ok %` | ≥95% | <90% — что-то с резолвом |
| `timeouts` | <0.1% от sent | растёт — прокси флапает |
| latency p95 | <10ms (DIRECT), <30ms (через прокси) | >100ms — туннель деградирует |
| latency p99 | <20ms (DIRECT), <100ms (proxy) | >300ms — bottleneck |
| `Δ alive` (наш патч) | ≈0 за тест | устойчиво >0 без затухания за 30s idle = **утечка** |

### NXDOMAIN — это нормально

Часть доменов в `out-of-group` отдаёт `NXDOMAIN` (например `nalog.gov.ru`, `kinopoisk.ru` — их NS ограничены гео). Часть в `in-group` могут возвращать NX из-за блокировок. Это не ошибка бенча.

### Δ alive — главный индикатор утечки

`run.sh` снимает `GET /connections/inner-stats` до и после каждого прогона. **`alive = joined − left`** показывает сколько Inner-conn (DNS-резолвинг внутри mihomo) сейчас в трекере.

- **Δ alive ≈ 0 (или ±10)** → пул разогрелся/поджался, нет накопления.
- **Δ alive растёт линейно с нагрузкой** → leak. Причём не любой, а именно тот класс, который мы лечили в `dns/dot.go` / `dns/doh.go` (см. [`research/mihomo-dns-inner-leak.md`](../../research/mihomo-dns-inner-leak.md)).

Чтобы убедиться что рост — pool fill, а не leak: подожди 30-40 секунд (наш idle-timeout) и снова сними `inner-stats`. Если `alive` упал — это был warmup. Если не падает — настоящий leak.

## Что бенч **не** проверяет

- Не валидирует ответы (что A-запись реальная, не fake-IP).
- Не проверяет route/iptables/ipset — для этого см. router-snapshot.
- UDP-only по умолчанию (DNS over 53). Для TCP-фрагмента стека — флаг `-tcp`, но 53/tcp на роутере magitrickled тоже принимает.

## Регенерация списков доменов

`data/in-group.txt` и `mix.txt` сделаны из правил MagiTrickle. Если правила сильно изменились — пересоздай:

```bash
# берём свежий snapshot
bash .claude/skills/router-snapshot/scripts/snapshot.sh dns-bench-rebuild

# извлекаем 50 доменов (стратифицированная выборка)
SNAP=$(ls -td .tmp/snapshots/dns-bench-rebuild-* | head -1)
PYTHONIOENCODING=utf-8 python3 -c "
import re, glob
text = open(r'$SNAP/magitrickle-config.yaml', encoding='utf-8').read()
pairs = re.findall(r'type:\s*(namespace|domain)\s*\n\s*rule:\s*[\'\"]?([^\'\"\n]+?)[\'\"]?\s*\$', text, re.MULTILINE)
domains = sorted(set(r.strip().lower() for t,r in pairs if r.strip() and '/' not in r))
step = max(1, len(domains)//50)
sample = domains[::step][:50]
open('tools/dns-bench/data/in-group.txt','w',encoding='utf-8').write('\n'.join(sample)+'\n')
print(f'обновлён: {len(sample)} доменов')
"
```

Для `out-of-group.txt` — ручной список топ-RU/нейтральных доменов с фильтром по in-group namespace (см. как сделано первый раз в этом проекте, в [`research/mihomo-dns-inner-leak.md`](../../research/mihomo-dns-inner-leak.md), шаг 1).

## Типовой workflow при подозрении на регрессию

```bash
# 1. baseline до нагрузки
ssh -p 222 root@10.9.0.1 'curl -s :9090/connections/inner-stats'

# 2. полный профиль
cd tools/dns-bench && ./run.sh all 100 30s

# 3. ждём 60 сек (idle cleanup)
sleep 60

# 4. фиксируем что pool схлопнулся
ssh -p 222 root@10.9.0.1 'curl -s :9090/connections/inner-stats'

# 5. snapshot роутера для коррелятов (conntrack, конфиги)
bash .claude/skills/router-snapshot/scripts/snapshot.sh post-bench
```

Если что-то аномальное — открыть [`docs/router-debug-playbook.md`](../../docs/router-debug-playbook.md) и идти по чек-листу.
