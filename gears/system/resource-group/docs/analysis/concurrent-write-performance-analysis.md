# Анализ медленной записи resource-group под конкурентной нагрузкой

## Область анализа

Документ рассматривает write-path модуля `resource-group` с точки зрения:

- длительности транзакций;
- количества SQL round-trips;
- write amplification closure table;
- конфликтов `SERIALIZABLE`/SSI и повторного выполнения транзакций;
- использования connection pool;
- поведения при hotspot-нагрузке на один parent/subtree/resource.

Это статический анализ реализации. В проекте нет воспроизводимого benchmark на реальном PostgreSQL с параллельными
writers, поэтому конкретные p95/p99 и TPS должны быть измерены отдельно.

Связанный анализ корректности:
[transaction-isolation-analysis.md](./transaction-isolation-analysis.md).

## Главный вывод

Основная причина медленной конкурентной записи — не стоимость инструкции
`BEGIN ISOLATION LEVEL SERIALIZABLE` сама по себе. Основная проблема — большое число последовательных запросов внутри
длинной транзакции.

Для больших subtree текущая реализация:

- многократно читает один и тот же closure snapshot;
- выполняет N+1-проверки глубины;
- вставляет closure rows по одной;
- удаляет subtree построчно;
- держит DB connection во время вызова `TypesRegistryClient` и компиляции JSON Schema;
- при `40001` повторяет весь объём работы с самого начала.

`SERIALIZABLE` превращает эти уже дорогие транзакции в retry-amplified workload. Снижение isolation level без устранения
N+1 и write amplification даст ограниченный эффект и может нарушить корректность.

## Модель стоимости операций

Обозначения:

- `N` — количество узлов в перемещаемом/удаляемом subtree, включая корень;
- `D` — количество descendants без корня, то есть примерно `N - 1`;
- `A` — количество ancestors нового parent, включая self-row parent;
- `P` — количество allowed parent types;
- `M` — количество allowed membership types.

Оценки ниже показывают порядок количества DB statements/round-trips, а не точное число для каждого optional branch.

| Операция             |             Текущая стоимость | Основной источник                                                       |
|----------------------|------------------------------:|-------------------------------------------------------------------------|
| Create child         | примерно `10–15 + A` запросов | повторные type/group reads и поштучная вставка ancestor closure rows    |
| Move subtree         |                 `O(2D + A×N)` | две проверки на descendant плюс одна INSERT на каждую новую closure row |
| Force delete subtree |          примерно `4N + O(1)` | memberships, два closure DELETE и group DELETE для каждого узла         |
| Create/update type   |             `O(P + M)` INSERT | junction rows вставляются по одной                                      |
| Membership add       |         примерно 6–9 запросов | раздельные group/type/membership/tenant reads                           |

При `N = 10 000`, `A = 10` move способен породить порядка 100 000 отдельных closure INSERT, не считая validation/read
queries. Это несовместимо с заявленным в DESIGN предположением о subtree до 10K как об обычном поддерживаемом случае.

## Move subtree: главный write bottleneck

### Повторное вычисление глубины

В `move_group_internal_impl` сначала загружаются все descendants:

```text
get_descendant_ids(group_id)
```

После этого для каждого descendant отдельно выполняются:

```text
is_descendant(group_id, desc_id)
get_relative_depth(group_id, desc_id)
```

`is_descendant` здесь избыточен: все элементы уже пришли из
`WHERE ancestor_id = group_id`. Relative depth уже содержится в тех же closure rows.

Стоимость этой части — примерно `1 + 2D` запросов. Она может быть заменена одним:

```sql
SELECT MAX(depth)
FROM resource_group_closure
WHERE ancestor_id = $group_id
```

Или одним чтением всех `(descendant_id, depth)`, которое затем переиспользуется для validation и rebuild.

### Повторное чтение subtree

Один и тот же логический subtree читается:

- для depth validation;
- внутри `rebuild_subtree_closure`;
- ещё раз через выборку всех paths для descendants.

Это увеличивает transaction duration и размер SSI read set. Нужен единый
`MovePlan`, загружающий:

- subtree IDs и relative depths;
- old external ancestors;
- new parent ancestors;
- max subtree depth;
- old/new parent metadata.

После получения плана проверки и mutation должны переиспользовать его, не повторяя запросы.

### Поштучная вставка closure rows

`rebuild_subtree_closure` материализует `A×N` `ActiveModel` в памяти, затем вызывает
`secure_insert` для каждой строки отдельно (`group_repo.rs:985–1005`).

Последствия:

- `A×N` network round-trips;
- `A×N` parse/bind/execute cycles;
- большой Rust `Vec<ActiveModel>`;
- большое transaction window;
- высокая вероятность `40001` ближе к commit, когда почти вся работа уже сделана.

Предпочтительная реализация — одна set-based операция:

```sql
INSERT INTO resource_group_closure (ancestor_id, descendant_id, depth)
SELECT pa.ancestor_id,
       st.descendant_id,
       pa.depth + 1 + st.depth
FROM resource_group_closure pa
         CROSS JOIN resource_group_closure st
WHERE pa.descendant_id = $new_parent_id
  AND st.ancestor_id = $moved_group_id;
```

Так как project guidelines запрещают plain SQL в gear repositories, реализацию следует сделать через:

- SeaQuery `INSERT ... SELECT`, если нужная конструкция поддерживается;
- либо новый проверенный helper в `toolkit-db`;
- как промежуточный вариант — `insert_many` с chunking.

Даже chunked `insert_many` по 500–2 000 rows уменьшит 100 000 round-trips до 50–200, хотя set-based `INSERT SELECT`
остаётся предпочтительным вариантом.

#### Откуда берутся 100 000 строк

Пусть:

- `N` — число узлов в переносимом subtree, включая его root;
- `A` — число предков нового parent, включая сам parent;
- `S(d)` — относительная глубина descendant `d` от root переносимого subtree;
- `P(a)` — глубина нового parent от ancestor `a`.

После attach для каждой пары `(a, d)` должна существовать closure row:

```text
(ancestor_id = a,
 descendant_id = d,
 depth = P(a) + 1 + S(d))
```

Поэтому число **новых внешних closure rows** равно:

```text
rows_to_insert = A × N
```

Например, если subtree содержит 10 000 узлов, а новый parent находится на глубине 9 от root, в closure имеются 10 строк
с его предками, включая self-row. Тогда:

```text
A × N = 10 × 10 000 = 100 000
```

Фраза «при глубине 10» требует уточнения: множитель определяется глубиной **нового parent**, а не глубиной переносимого
subtree. При глубине parent 3 будет `4 ×
10 000 = 40 000` строк. Высота самого subtree дополнительно ограничивает, насколько глубоко его разрешено присоединить
при настроенном `max_depth`.

Внутренние связи subtree при move не пересоздаются. Например, строки между root subtree и его descendants остаются на
месте. Удаляются старые и добавляются новые связи только с внешними ancestors. При переносе в root новых внешних строк
вообще нет.

В текущей Rust-реализации `A × N` означает сразу две разные стоимости:

1. PostgreSQL физически должен записать `A × N` строк, обновить PK/index, WAL и MVCC metadata.
2. Приложение выполняет `A × N` отдельных `secure_insert`, то есть столько же SQL statements и client/server
   round-trips.

Set-based SQL устраняет вторую стоимость, но не первую. Поэтому ускорение может быть очень большим, однако оно не будет
равно `100 000×`: база всё равно материализует 100 000 closure rows.

#### Сравнение с `platform-api`

В
`~/ws/core-workspace/src/platform/aps/platform-api/internal/app/logic/repository/repo_group.go`
функция `moveUnitSubtree` уже реализует этот алгоритм в правильной set-based форме:

```sql
INSERT INTO groups_closure (...)
SELECT gc_parent.parent_id,
       gc_child.child_id,
       gc_parent.depth + gc_child.depth + 1, ...
    FROM groups_closure AS gc_parent, groups_closure AS gc_child
WHERE gc_parent.child_id = $new_parent_id
  AND gc_child.parent_id = $moved_group_id;
```

Это тот же декартов продукт `A × N`, но PostgreSQL строит его внутри одного statement:

- исходные closure rows не передаются в приложение;
- не создаётся `Vec` из 100 000 ORM-моделей;
- нет 100 000 bind/execute/await;
- statement использует один snapshot;
- SERIALIZABLE transaction становится существенно короче.

Там же старые внешние paths удаляются одним set-based `DELETE` с двумя subquery. Для create аналогичный паттерн уже
применён в `initEntityGraph`: self-row и связи со всеми ancestors создаются одним `INSERT ... SELECT`.

Схему нельзя копировать буквально: `platform-api` хранит `tenant_id`/`graph_id` и поддерживает более сложную
graph-семантику, тогда как `resource-group` опирается на канонический single `parent_id`. Но ядро `moveUnitSubtree`
соответствует текущей closure-модели `resource-group` практически один к одному.

Этот SQL решает проблему производительности statement amplification, но сам по себе не заменяет concurrency control. В
частности, один set-based statement:

- не предотвращает concurrent move одного subtree;
- не сериализует конкурирующие attach к одному parent;
- не заменяет проверку cycle/max depth на согласованном состоянии.

Поэтому безопасная последовательность изменений:

1. сначала заменить row-by-row rebuild на set-based `DELETE` и `INSERT SELECT`, сохранив текущую транзакцию и retry
   semantics;
2. измерить duration, WAL, lock wait и `40001`;
3. только затем решать, можно ли снижать isolation и какие точечные row/advisory locks необходимы.

### Лишние read-back запросы

`GroupRepository::insert` вызывает `secure_insert`, игнорирует возвращённую модель, а затем повторно читает строку по ID
(`group_repo.rs:652–658`).

После этого service снова вызывает `find_by_id`, который дополнительно разрешает type path. Аналогичные повторные reads
присутствуют после update.

Нужно:

- возвращать model непосредственно из `secure_insert`;
- передавать уже известный type path в mapping;
- использовать `RETURNING`/single-row ActiveModel update вместо `update_many +
  SELECT`, где это возможно.

## Force delete: линейное число транзакционных round-trips

Текущий алгоритм для каждого узла subtree:

1. удаляет memberships;
2. удаляет closure rows, где узел ancestor;
3. удаляет closure rows, где узел descendant;
4. отдельным вторым циклом удаляет сам group.

Итого — примерно `4N` statements.

Предлагаемая форма:

1. один batch DELETE memberships для всех subtree IDs;
2. один или два batch DELETE closure rows;
3. удаление groups по уровням от leaves к root — один DELETE на depth level.

Чтобы удалить все groups одним statement независимо от физического порядка проверки FK, можно рассмотреть `DEFERRABLE`
parent FK, но это отдельное изменение схемы и семантики. Более консервативный вариант — depth-batched delete: при
`max_depth = 10` вместо 10 000 group DELETE будет не более примерно 10 statements.

## Create group

Create child выполняет:

- несколько разрешений одного type;
- загрузку parent и parent type;
- запрос глубины;
- optional count children;
- INSERT group и повторный SELECT;
- INSERT self closure;
- чтение parent ancestors;
- одну INSERT на каждого ancestor;
- финальный read group и type.

Для средней глубины 3 это уже двузначное число round-trips.

Оптимизации:

- загружать type один раз;
- возвращать inserted group без повторного SELECT;
- `INSERT ... SELECT` для ancestor closure rows;
- при включённом `max_width` материализовать `child_count` на parent и изменять его атомарно;
- не запускать внешний metadata lookup после открытия DB transaction.

Материализованный `child_count` позволяет заменить predicate:

```text
COUNT(children) < max_width
```

на атомарное изменение одной строки:

```sql
UPDATE resource_group
SET child_count = child_count + 1
WHERE id = $parent
  AND child_count < $max_width RETURNING child_count;
```

Это уменьшает predicate contention и даёт естественную hotspot-сериализацию на parent row. Но счётчик должен изменяться
в той же транзакции при create/move/delete и иметь reconciliation/integrity test.

## Types и metadata validation

### Junction N+1

Allowed parent/membership junction rows вставляются последовательным циклом. Обычно
`P` и `M` малы, поэтому это не главный bottleneck, но под массовым type provisioning следует применять `insert_many`.

### Внешний вызов внутри transaction

`validate_metadata_via_gts` вызывает:

```text
types_registry.get_type_schema(type_code).await
```

после открытия `SERIALIZABLE` transaction. Затем JSON Schema компилируется через
`jsonschema::validator_for`.

Это означает, что DB connection и SSI snapshot удерживаются во время:

- ClientHub/RPC lookup;
- построения effective schema;
- компиляции schema;
- validation metadata.

При retry вызов и compilation повторяются.

Рекомендуется:

1. получить resolved schema и её immutable version/hash до `BEGIN`;
2. кэшировать compiled validator по `(type_code, schema_version)`;
3. внутри транзакции проверять только актуальность version/hash, если требуется строгая согласованность с type update;
4. выполнять чистую validation до открытия DB transaction.

Это сокращает transaction window без ослабления DB invariants.

## Retry amplification

`transaction_with_retry` делает до трёх полных попыток без backoff. Если вероятность конфликта одной попытки равна `p`,
ожидаемое число выполненных попыток с лимитом 3:

```text
E[attempts] = 1 + p + p²
```

Примеры:

| Вероятность конфликта | Среднее число попыток | Лишняя работа |
|----------------------:|----------------------:|--------------:|
|                   10% |                  1.11 |           11% |
|                   30% |                  1.39 |           39% |
|                   60% |                  1.96 |           96% |
|                   90% |                  2.71 |          171% |

Под реальным hotspot попытки не независимы: немедленный retry часто снова встречается с теми же конкурентами. Поэтому
фактическое amplification может быть хуже этой модели.

Нужны:

- небольшой exponential backoff с jitter для `40001`/deadlock;
- метрика `attempt_count`;
- ограничение in-flight hierarchy mutations;
- разные retry budgets для короткого create и крупного subtree move;
- запрет автоматического retry после заранее заданного transaction deadline.

Backoff должен быть коротким, но ненулевым, например миллисекундного порядка. Точные значения выбираются по benchmark, а
не статически.

## Connection pool и queueing

Default `toolkit-db` pool имеет `max_conns = 10` и `acquire_timeout = 30s`
(`libs/toolkit-db/src/lib.rs:288–294`). Deployment может переопределять значения, но в репозитории нет production
PostgreSQL-конфигурации именно для resource-group.

Длинный move занимает одно соединение на всю попытку. Десять одновременных moves могут занять весь pool; последующие:

- create/membership writes;
- reads для AuthZ;
- retries уже конфликтующих транзакций

будут ждать connection.

Увеличение `max_conns` без сокращения transaction duration обычно не решает проблему:

- увеличивается число одновременно активных SSI transactions;
- увеличивается число overlapping read/write sets;
- растёт частота `40001`;
- больше памяти тратится на predicate locks;
- база выполняет больше работы, которая затем откатывается.

Предпочтительнее:

- сначала уменьшить round-trips и transaction duration;
- затем ограничить concurrency тяжёлых mutations отдельным semaphore/admission controller;
- только после benchmark настраивать pool.

In-memory semaphore не является механизмом корректности и не заменяет SSI: он лишь снижает число одновременно
выполняемых тяжёлых операций на одном instance. При нескольких replicas база остаётся authoritative arbiter.

## SSI-specific contention

PostgreSQL создаёт predicate `SIReadLock` на фактически прочитанные tuple/page/ relation. Большие scans могут
укрупняться до page- или relation-level predicate locks, что увеличивает число ложных конфликтов.

Риск особенно высок для:

- больших subtree reads;
- global tenant-root lookup с join и prefix predicate;
- type hierarchy safety scans;
- больших `IN (subtree_ids...)`.

Нужно проверить реальные query plans. Если planner выбирает sequential scan, одна mutation может получить relation-level
predicate lock и конфликтовать с логически независимыми tenants.

## Индексы

Существующая схема имеет хорошие базовые индексы:

- closure PK `(ancestor_id, descendant_id)`;
- closure index `(descendant_id)`;
- group index `(parent_id)`;
- membership index `(gts_type_id, resource_id)`.

Кандидаты для проверки через `EXPLAIN (ANALYZE, BUFFERS)`:

- covering closure index
  `(descendant_id, ancestor_id) INCLUDE (depth)` — ancestor lookup без heap fetch;
- parent index `(parent_id) INCLUDE (id, gts_type_id, tenant_id)` для child scans;
- membership index
  `(gts_type_id, resource_id) INCLUDE (group_id)` для tenant compatibility lookup;
- materialизованный признак tenant-root и unique partial index.

Текущий tenant-root predicate зависит от join с `gts_type.schema_id starts_with`, поэтому unique partial index
непосредственно на существующем представлении невозможен. Можно денормализовать `is_tenant_type`/`is_tenant_root` в
`resource_group` и обеспечить уникальность схемой. Это одновременно уберёт глобальный predicate scan из горячей write
transaction.

Индексы являются вторичной оптимизацией. Они не компенсируют десятки тысяч отдельных INSERT/DELETE statements.

## Несоответствия документации реализации

DESIGN утверждает:

- closure pattern устраняет N+1;
- subtree до 10K поддерживаются;
- transaction timeout равен 5s;
- exhaustion возвращает `ServiceUnavailable`;
- PostgreSQL concurrency tests проверяют retry.

В текущей реализации:

- read-path closure действительно batch-oriented, но write-path содержит N+1;
- hard cap на subtree отсутствует;
- в `PoolCfg` нет `statement_timeout`, `lock_timeout` или transaction timeout;
- exhausted DB error отображается в canonical Internal/HTTP 500;
- реальные PostgreSQL barrier-based concurrency tests отсутствуют.

Эти расхождения важны для capacity planning: заявленные гарантии сейчас нельзя использовать как подтверждённые
эксплуатационные свойства.

## План оптимизации

### P0 — измеримость

До изменения isolation/locking добавить:

- histogram transaction duration по operation и attempt;
- pool acquire wait;
- statement count на transaction;
- subtree size и ancestor count;
- closure rows read/deleted/inserted;
- serialization failure/deadlock count;
- retry attempts и exhausted retries;
- metadata validation duration;
- commit duration;
- PostgreSQL `pg_stat_statements`;
- sampling `pg_locks` для `SIReadLock`.

Нужны отдельные метрики `useful_commits/sec` и `attempts/sec`: высокий raw query throughput при большом числе rollback
не является хорошей производительностью.

### P1 — убрать алгоритмическую избыточность

1. Заменить `2D` depth validation на один `MAX(depth)` или уже загруженный
   `(descendant_id, depth)`.
2. Ввести единый `MovePlan`, исключив повторные subtree/parent/type reads.
3. Заменить closure row-by-row INSERT на `INSERT ... SELECT`.
4. Заменить create ancestor loop на `INSERT ... SELECT`.
5. Batch-delete memberships и closure.
6. Delete groups по depth batches.
7. Убрать повторные SELECT после INSERT/UPDATE.

Это самый большой и наименее спорный источник ускорения.

### P2 — сократить transaction window

1. Вынести GTS schema resolution/compilation до `BEGIN`.
2. Кэшировать compiled JSON Schema по version/hash.
3. Разделить metadata-only update и structural move.
4. Не включать response enrichment/read-back в write transaction, если response можно построить из authoritative
   mutation result.
5. Ввести реальные `statement_timeout`, `lock_timeout` и общий transaction deadline.

### P3 — управлять конфликтами

1. Добавить backoff+jitter.
2. Ввести admission control для тяжёлых moves/deletes.
3. Материализовать `child_count`, если `max_width` реально используется.
4. Материализовать tenant-root uniqueness как DB constraint.
5. Исправить memberships через ownership/guard row.
6. После сокращения transaction window повторно оценить необходимость
   `SERIALIZABLE` по каждой операции.

### P4 — isolation/locking specialization

Только после P1–P3:

- create type → `READ COMMITTED`;
- metadata-only group update → `READ COMMITTED` + row lock/CAS;
- membership → `READ COMMITTED` + guard row;
- non-force delete → `READ COMMITTED` + target lock/FK;
- hierarchy move оставить `SERIALIZABLE`, пока benchmark не докажет преимущество полного deterministic row-lock
  protocol.

## Benchmark plan

Benchmark должен выполняться на реальном PostgreSQL, а не SQLite.

### Dataset

- 100K, 1M и репрезентативная часть 5M groups;
- depth distributions 3 и 10;
- subtree sizes 1, 10, 100, 1K, 10K;
- membership table достаточного размера для реалистичных indexes/cache hit ratio.

### Workloads

1. Независимые tenants — baseline горизонтальной масштабируемости.
2. Один hotspot parent — массовый create child.
3. Один hotspot subtree — conflicting moves.
4. Смешанный workload:
    - 70% reads;
    - 20% create/membership;
    - 8% update;
    - 2% move/delete.
5. Type update одновременно с group writes.
6. Cold-cache и warm-cache режимы.

### Concurrency

`1, 2, 4, 8, 16, 32, 64` clients при фиксированном pool, затем отдельный sweep pool size.

### Измерения

- useful TPS;
- p50/p95/p99 end-to-end;
- pool queue time;
- DB execution/commit time;
- statements per committed operation;
- rows changed per operation;
- `40001` и retry amplification;
- exhausted failures;
- CPU, IOPS, WAL bytes, buffer hit ratio;
- deadlocks и lock wait time.

### Сравниваемые варианты

1. Текущая реализация.
2. Только batching/set-based closure.
3. Batching + short transaction window.
4. Вариант 3 + backoff/admission control.
5. Selective `READ COMMITTED`.
6. При необходимости — deterministic row-lock hierarchy prototype.

## Ожидаемый порядок эффекта

По статическому анализу ожидаемый приоритет таков:

1. set-based closure rebuild;
2. batch force-delete;
3. устранение `2D` validation queries;
4. внешний metadata lookup вне transaction;
5. устранение повторных read-back;
6. backoff и admission control;
7. selective lowering isolation;
8. точечная настройка indexes/pool.

Таким образом, начинать с замены `SERIALIZABLE` на `READ COMMITTED` не следует. Сначала необходимо уменьшить стоимость
одной попытки. После этого SSI conflicts станут короче и дешевле, а benchmark покажет, остаётся ли isolation level
существенным ограничителем либо bottleneck уже устранён.
