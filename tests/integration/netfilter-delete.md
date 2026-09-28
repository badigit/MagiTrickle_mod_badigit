# Проверка удаления netlink/ipset

Регрессии mt-j8p / mt-7e1. Тесты используют настоящее ядро, без fake netlink.

## Полный прогон в Linux / WSL

Из `src/backend`, Go и root должны быть доступны:

```sh
timeout 180 go test -tags integration -c -o /tmp/netfilter-delete.test ./utils/netfilterTools
sudo modprobe xt_TPROXY
sudo modprobe xt_socket
sudo unshare -n env MT_DELETE_TEST_NETNS=1 /tmp/netfilter-delete.test -test.run '^TestDelete' -test.v -test.timeout 60s
```

Нужны `iptables-save/restore`, `ip6tables-save/restore` и поддержка ipset,
TPROXY, socket в ядре. Отдельный netns обязателен: тест смены шлюза меняет
main-таблицу внутри него. Обычный `go test -tags testing` эти тесты не запускает.

Проверяется:

- повторное удаление IPv4/IPv6 entries, routes, policy rules;
- метрики маршрутов 0, 10 и 20;
- смена шлюза после удаления старого маршрута извне;
- реальный `EPERM` из дочернего процесса с UID/GID 65534 для обоих режимов;
- два цикла TPROXY Enable/Disable с реальными iptables/ipset, проверкой
  маршрутизации по fwmark и удалением правил/маршрутов ядром до Disable.

## Ограниченная проверка на роутере без netns

Собрать тестовый бинарник под архитектуру роутера (например,
`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -tags integration -c ...`).
Передать в отдельный временный каталог, доступный UID 65534 для исполнения.
Запускать **только** этот тест, с явным opt-in:

```sh
MT_DELETE_ROUTER_PROBE=1 ./netfilter-delete.test -test.run '^TestDeleteRouterProbeKernel$' -test.v -test.timeout 45s
```

Проба проверяет свободную таблицу и создаёт в ней только маршруты без policy
rules, а также отдельные ipset с именем на основе PID. Боевые цепочки iptables,
интерфейсы и сервисы не изменяются. Проверяет оба режима удаления, восстановление
маршрута, IPv4/IPv6, метрики и `EPERM`. Это **не** проверка полного рестарта демона
или прохождения клиентского трафика. После прогона проверить отсутствие тестовых
объектов и удалить бинарник.

Проверено 28.09.2026: WSL `6.18.33.2-microsoft-standard-WSL2` и Keenetic
`4.9-ndm-5`. На обоих ядрах отсутствующий IPv6 default route с метрикой 0 дал
`ENOENT`, с метриками 10/20 — `ESRCH`; IPv4 дал `ESRCH` во всех трёх случаях.
