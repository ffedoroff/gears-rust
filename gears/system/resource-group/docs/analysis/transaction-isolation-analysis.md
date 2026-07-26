# Анализ уровня изоляции транзакций в resource-group

## Вывод

Полный отказ от `SERIALIZABLE` для иерархических операций сейчас небезопасен. Для
`create/move/delete` он действительно защищает существенные multi-row инварианты:
отсутствие циклов, корректность closure table, `max_width/max_depth` и уникальность
tenant-root.

Но использовать `SERIALIZABLE` как единый уровень для всех записей необязательно.
В текущей реализации он местами избыточен, местами реализован неполно, а один
критический инвариант memberships вообще не защищён транзакцией.

Наиболее разумная стратегия:

- оставить `SERIALIZABLE + retry` для структурных изменений иерархии;
- перевести простые операции на `READ COMMITTED` с ограничениями и row locks;
- отдельно исправить конкурентную запись memberships;
- не использовать внешний distributed lock для коротких DB-транзакций.

## Что происходит сейчас

`SERIALIZABLE` используется в:

- создании групп — `resource-group/src/domain/group_service.rs:150`;
- update/move/delete групп — `resource-group/src/domain/group_service.rs:263`;
- create/update типов — `resource-group/src/domain/type_service.rs:91`.

Но:

- membership add не имеет общей транзакции;
- type delete выполняет check и delete вне транзакции;
- чтение hierarchy выполняет несколько запросов без единого snapshot;
- retry есть у group-операций, но отсутствует у create/update type.

PostgreSQL `SERIALIZABLE` реализован через SSI: чтения не блокируют записи, но
PostgreSQL отслеживает predicate read/write dependencies и отменяет одну транзакцию
с `40001`, если результат нельзя представить как последовательное выполнение. Это
именно тот механизм, который нужен для write-skew и phantom-зависимостей в closure
table.

Официальная документация:
[PostgreSQL Transaction Isolation](https://www.postgresql.org/docs/current/transaction-iso.html).

## Где SERIALIZABLE действительно оправдан

| Операция | Конкурентная проблема | Оценка |
|---|---|---|
| Create child | Два create одновременно проходят `count_children < max_width` | Нужен SSI или блокировка parent |
| Move subtree | Одновременные `A → B` и `B → A` могут обе пройти проверку цикла | `SERIALIZABLE` оправдан |
| Move ancestor + descendant | Closure snapshot одного move устаревает из-за второго | `SERIALIZABLE` оправдан |
| Create under moving parent | Create копирует старые ancestors, move перестраивает subtree | `SERIALIZABLE` оправдан |
| Tenant-root creation | Две транзакции видят отсутствие root и обе вставляют его | Нужен SSI, guard row или DB constraint |
| Type update vs group creation | Тип запрещает parent placement одновременно с созданием такой связи | Нужна общая координация |
| Force delete vs subtree mutation | Набор удаляемых descendants может измениться | Нужен SSI или блокировка всего subtree |

Особенно показателен move: проверка цикла выполняется по closure table, после чего
closure удаляется и строится заново (`group_service.rs:1085`,
`group_repo.rs:905`). Простого `SELECT FOR UPDATE` только над перемещаемой группой
недостаточно — конфликт может затрагивать descendants, ancestors и новый parent.

`REPEATABLE READ` не является подходящей заменой: в PostgreSQL он даёт стабильный
snapshot, но допускает serialization anomalies/write skew. Для business invariants
PostgreSQL рекомендует либо `SERIALIZABLE`, либо тщательно спроектированные
explicit locks.

## Где уровень избыточен

### Create type

Комментарий в `type_service.rs:42` связывает `SERIALIZABLE` с атомарностью
последовательности вставок. Но атомарность обеспечивает сама транзакция, а не её
isolation level.

Для create type достаточно:

- `READ COMMITTED`;
- `UNIQUE(gts_type.schema_id)`;
- FK на referenced types;
- корректного преобразования unique violation в `TypeAlreadyExists`.

Сейчас уникальность уже обеспечена схемой
(`m20260306_000001_initial.rs:23`).

### Update без изменения parent

Изменение только `name/metadata` не затрагивает closure table. Его можно выполнять
под `READ COMMITTED` через:

- `SELECT ... FOR UPDATE` строки группы;
- либо optimistic CAS: `UPDATE ... WHERE version = expected_version`.

Сейчас `update_group` всегда использует `SERIALIZABLE`, даже когда `parent_id` не
изменился.

### Delete type

FK `resource_group.gts_type_id ... ON DELETE RESTRICT` уже не позволяет удалить
используемый тип. Предварительный `COUNT` нужен для красивой ошибки, но не является
последней линией защиты.

Его можно выполнять под `READ COMMITTED` в одной транзакции, полагаясь на FK как
authoritative invariant.

## Критическая проблема memberships

Самая существенная найденная гонка находится вне `SERIALIZABLE`.

Алгоритм:

1. прочитать существующие tenants ресурса;
2. убедиться, что множество пусто или содержит target tenant;
3. вставить membership.

Это выполняется без транзакции (`membership_service.rs:128`,
`membership_service.rs:179`).

Возможна гонка:

```text
T1: memberships(resource X) = ∅
T2: memberships(resource X) = ∅
T1: INSERT group tenant A
T2: INSERT group tenant B
```

PK включает `group_id`, поэтому обе вставки успешно коммитятся. Инвариант
«resource принадлежит группам только одного tenant» нарушается.

`SELECT FOR UPDATE` существующих memberships не исправляет этот случай: при первой
membership блокировать ещё нечего.

Предпочтительное решение — материализовать ownership:

```text
resource_membership_tenant
  (gts_type_id, resource_id) PRIMARY KEY
  tenant_id NOT NULL
```

В одной `READ COMMITTED` транзакции:

1. `INSERT ... ON CONFLICT` ownership row;
2. заблокировать/read ownership row;
3. проверить `tenant_id`;
4. вставить membership.

Membership может дополнительно хранить `tenant_id` и ссылаться composite FK на
ownership row. Тогда инвариант обеспечивается схемой, а не check-then-act кодом.

Альтернатива — transaction-scoped PostgreSQL advisory lock по
`(gts_type_id, resource_id)`, но guard table лучше переносится между backend-ами и
легче тестируется.

## Возможен ли полный переход hierarchy на READ COMMITTED

Да, но только после введения строгого lock protocol.

Минимальный протокол:

- create child: `FOR UPDATE` parent;
- move: заблокировать в детерминированном UUID-порядке:
  - moved group;
  - весь subtree;
  - old/new parent;
  - строки ancestors, closure которых будет изменена;
- после получения блокировок заново прочитать closure и повторить
  cycle/depth/width checks;
- delete: блокировать target/subtree до проверки references и удаления;
- group create должен брать share-lock на используемые type rows;
- type update — exclusive-lock на соответствующий type row;
- везде соблюдать единый порядок блокировок.

SeaORM в проекте поддерживает `.lock(LockType::Update)`, например в
`mini-chat/src/infra/db/repo/chat_repo.rs:157`. `FOR UPDATE` блокирует найденные
строки до завершения транзакции, но не защищает отсутствие строки или произвольный
predicate — поэтому для root uniqueness и первой membership всё равно нужны
constraint/guard rows.

Официальная документация:
[PostgreSQL Explicit Locking](https://www.postgresql.org/docs/current/explicit-locking.html).

Такой протокол реализуем, но сложнее текущего SSI и требует блокировки потенциально
большого subtree. При заявленных subtree до 10K строк выигрыш не гарантирован:
abort/retry сменится ожиданием большого набора locks и риском deadlock.

## Почему distributed lock не рекомендуется

Встроенный `toolkit_db::Db::lock()` — не DB-native distributed lock. Он реализован
через lock-файл (`libs/toolkit-db/src/advisory_locks.rs:6`), поэтому:

- не координирует разные hosts/pods;
- может оставить stale-файл после аварии;
- не является fencing-механизмом.

Внешний distributed lock через cluster/Redis/Kubernetes/etcd добавит:

- вторую систему согласованности;
- failure window между lock и DB commit;
- необходимость fencing token;
- новые timeout/recovery сценарии.

Для короткой операции над одной PostgreSQL DB row locks, guard rows или SSI
надёжнее и проще. Внешний lock оправдан для длительных jobs, но не для
closure-table mutation.

## Дополнительные проблемы текущей реализации

1. **Type transactions не retry-aware.**  
   `create_type/update_type` используют `transaction_ref_mapped_with_config`, а не
   `transaction_with_retry`. Поэтому ожидаемый `40001` превращается в HTTP 500
   через `api/rest/error.rs:149`.

2. **Retry выполняется без backoff.**  
   Три попытки идут немедленно (`libs/toolkit-db/src/secure/db.rs:52`). На hotspot
   это может повторно столкнуть те же транзакции.

3. **Move transaction слишком длинная.**  
   Depth validation делает несколько запросов на каждого descendant, а closure
   rows вставляются по одной. Чем дольше `SERIALIZABLE` transaction, тем выше
   вероятность abort.

4. **Внутри DB-транзакции есть внешний async validation.**  
   Metadata validation через `types_registry` выполняется внутри retryable
   transaction (`group_service.rs:559`). Это увеличивает lifetime snapshot и
   повторяется при retry.

5. **Hierarchy reads не имеют единого snapshot.**  
   Closure IDs и сами groups читаются отдельными запросами
   (`group_repo.rs:546`). Move может закоммититься между ними. Если endpoint обязан
   возвращать один логический snapshot, ему нужен короткий
   `REPEATABLE READ READ ONLY`.

6. **Нет реальных PostgreSQL concurrency tests.**  
   Существующие service tests используют SQLite и проверяют последовательные
   сценарии. В документации concurrency tests заявлены, но тестов с barriers и
   параллельными move/create в кодовой базе нет.

## Рекомендуемое решение

### Ближайший безопасный вариант

- Оставить `SERIALIZABLE + retry` для:
  - create group;
  - parent-changing update;
  - move;
  - force delete;
  - type update, пока не введён общий type locking protocol.
- Перевести на `READ COMMITTED`:
  - create type;
  - metadata/name-only group update;
  - type delete в одной транзакции с FK как окончательной защитой;
  - non-force delete после row lock target group.
- Исправить memberships через ownership/guard table.
- Перевести type update на retry-aware helper либо явно отображать exhausted
  `40001` в `ABORTED/503`, но не в generic 500.
- Оптимизировать closure rebuild до batch operations и сократить количество
  запросов внутри transaction.

### Перед снижением isolation обязательно добавить PostgreSQL tests

Минимальная матрица:

- `A → B` одновременно с `B → A`;
- move ancestor одновременно с move descendant;
- create child одновременно с move parent;
- два create при `max_width=1`;
- два tenant-root create;
- force delete одновременно с create child/add membership;
- type update одновременно с group create;
- две первые memberships одного ресурса в разных tenants;
- два concurrent full-replacement update одного type.

После каждого теста нужно проверять не только успешность запросов, но:

- отсутствие циклов по `parent_id`;
- точное равенство closure table транзитивному замыканию `parent_id`;
- правильные depths;
- отсутствие лишних/missing closure rows;
- один tenant на `(resource_type, resource_id)`;
- число `40001`, retries, deadlocks и p95.

Итого: `SERIALIZABLE` для hierarchy сейчас обоснован и является более безопасным
вариантом, чем частичные `FOR UPDATE`. Но он не должен быть универсальным default
для type/simple-row операций и, главное, не компенсирует текущую race condition в
membership path. Наибольший практический выигрыш даст не полный переход на
`READ COMMITTED`, а выборочная декомпозиция isolation policy плюс перенос ключевых
инвариантов в constraints/guard rows.
