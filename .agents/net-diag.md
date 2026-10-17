# Качество нод, каналов и роутерного VPN

Для «проверь ноду/канал», потерь, retransmits, RTT/jitter, реконнектов или
BBR/pacing/shaper сначала читай общий навык `net-diag` в infra-docker:
[SKILL.md](C:/Users/Dee/GitHub/infra-docker/tools/skills/net-diag/SKILL.md),
[процесс](C:/Users/Dee/GitHub/infra-docker/tools/net-diag/WORKFLOW.md).
На другой машине найди локальный checkout infra-docker; не копируй методику сюда.

Здесь владелец кода MT и роутерных улик: `tools/reconnect-debug/README.md`,
watchdog, conntrack, RST и синхронные captures. Общий net-diag ссылается обратно.
Конфиги конкретного роутера и доставка —
[keenetic_config](C:/Users/Dee/GitHub/keenetic_config/AGENTS.md);
код прокси — [mihomo](C:/Users/Dee/GitHub/mihomo/FORK.md).
Диагностика не разрешает постоянный тюнинг. Сначала оцени путь без системных
изменений, затем предложи узкий эксперимент и проверь до/после в порученной области.
