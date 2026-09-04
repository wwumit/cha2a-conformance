# did:cha2a Conformance Suite

did:cha2a 方法规范的 conformance 套件——**把规范 §8"声称有 test vectors"变成"实有"**。
独立自证体系：byte-stable 测试向量 + 双实现（Python/Node）独立判卷互锁 + MANIFEST 字节钉住 + CI 防漂移；向量逐条追溯规范条款（§x.y），负向向量占比 >1/3。

## 状态（2026-09-03 更新）

| 项 | 状态 |
|---|---|
| 离线向量 | **68 fixtures（+8 §4.2.1 federation 语义、+6 §4.7 content-integrity verify），双验证器 68/68 PASS + parity 互锁一致** |
| live 旧站（生产，只读）| **10/10 PASS**（规范参考实现达标）|
| live 新站（火山，只读）| **5/8 PASS**（3 项规范-实现缺口，见 conformance.json）|
| 负向向量占比 | >1/3（篡改/伪造/非法/边界必须 REJECT）|
| 确定性 | 生成器重跑字节一致（git diff 为空）+ MANIFEST.sha256 钉住 |
| 双实现互锁 | Python（cryptography）+ Node（node:crypto）独立判卷，parity 一致 |
| CI | ✅ GitHub Actions（push/PR 自动跑：双验证器+parity 三断言+MANIFEST+计数防漂移+跨仓版本一致性+规范→向量反向覆盖）|

## 用法

```bash
# 1. 生成向量（确定性）
python3 scripts/generate_fixtures.py
# 2. 生成 MANIFEST（改向量后必须重新生成）
(sha256sum fixtures/*.json vectors/*.json) > MANIFEST.sha256
# 3. 双验证器
python3 verifiers/python/verify.py fixtures --manifest MANIFEST.sha256
node verifiers/node/verify.mjs fixtures --manifest MANIFEST.sha256
# 4. 互锁
python3 scripts/parity.py
# 5. 防漂移（CI 同款：计数/JSON/README 声称=实有）
python3 scripts/check_consistency.py
# 6. live（只读，旧站生产安全）
bash live/live.sh --host https://compliancehub.cn --label legacy-production
bash live/live-new.sh --host http://127.0.0.1:5000   # 火山本机
```

## 覆盖矩阵（68 向量 ↔ 规范条款）

| 规范条款 | 向量数 | 内容 |
|---|---|---|
| §3.1 ABNF 语法 | 16 | 12 类型 valid + 大写方法/空 id/空格/fragment |
| §3.4 Identifier normalization | 6 | resource-id 大写合法 / Foo≠foo / 非 ASCII REJECT / scoped 字节保持 / 解析大小写不匹配 404 / 类型大写 REJECT |
| §4.5 出站签名 | 3 | Ed25519 有效/篡改/伪造 |
| §5.2 discovery | 2 | 结构完整/缺 publicKeys |
| §4.6 L0-L4 | 8 | L0-L4 判定 + 同一 verifier 非 L4 + 未注册 verifier 非 L4 + 撤销 fail-closed |
| §4.6 evidence | 3 | 字段完整 / predicate-subject 不匹配 REJECT / 缺 evidenceRef REJECT |
| §4.1 Create | 7 | 5 类型 valid + 非法类型 + 重复 |
| §4.2 Read | 4 | 已注册/未注册 404/语法 400/deactivated |
| §4.3 Update | 2 | 已注册/未注册 |
| §5 DID 文档 | 3 | 结构完整/缺 verificationMethod/非 Ed25519 |
| §4.2.1 federation（v0.4）| 8 | trust lookup 行为合规：本地优先 / 仅显式 peer 转发 / 无 peer fail-closed / peer 不可达错误透传（不编造） |
| §4.7 content-integrity（verify，evidence 节）| 6 | 四检查判定：指纹匹配 / content-integrity 背书（verifier 已注册）/ level≥1 / 撤销 fail-closed |

**计数由 generate_fixtures.py 输出维护——README 声称 = fixture 实有（防"声称≠实有"）。**

## live 缺口（如实，来自新站 live 5/8）

1. `/.well-known/cha2a`（§5.2 discovery）——新站未实现（旧站已实现）
2. `number-ranges` 端点（§3.3 号段授权机制）——新站未实现（旧站已实现，grant 记录可核验）
3. evidence/query 返回字段 `did` vs 规范/旧站 `subject`——新旧站/规范不一致，待核对

## notCovered（诚实，详见 conformance.json；条数=25，与 conformance.json 一致）

- §4.6 L4 生态状态（需 ≥2 独立真实 verifier，fixtures 证明不了）
- §3.3 号段真实运营（无真实号段；live 只验证机制，grant 记录可核验）
- §4.6 disclosure consistency（L4 额外条件，场景未模拟）
- §6 Security Considerations（实现侧安全要求：密钥轮换 overlap/fail-closed 验证/撤销消费/防重放等——离线协议向量无法证明，属实现核对 B 项与 live 覆盖）
- §7 Privacy Considerations（实现侧隐私要求——离线协议向量无法证明，属实现核对 B 项）
- §4.2.1 federation 真实跨 registry 互操作（offline 语义已由 federation 向量覆盖；无第二真实部署，live 互操作未验证）
- §4.8 runtime attestation runtime-side（reserved，无运行行为；registry-side content-integrity 在 §4.7 evidence 节，已有 verify 向量）
- §7.4 Correlation across resources（隐私实现侧——属实现核对 B 项）
- §7.5 Federation 运营要求（trust-lookup 语义与 §4.2.1 同源已有向量；号码解析中继身份等运维约束属 B 项/live）
- §9.3 live-endpoint conformance（由 live/ 脚本对运行中参考实现实测，非离线向量）
- §9.5 conformance assets 发布要求（第三方实现自证要求；本套件为参考实现提供 assets）
- §7.1 Public registry records（隐私实现侧，B 项）
- §7.2 Resolution traffic（隐私实现侧，B 项）
- §7.3 Bundle download（隐私实现侧，B 项）
- §6.8 Transparency log（实现侧安全，B 项）
- §6.9 Registry 密钥泄露（实现侧安全，B 项）
- §6.11 Post-quantum（实现侧安全，B 项）
- §1.3 能力检索（MAY 端点 + SHOULD 短标签，语义指导不钉向量；端点行为 live 实测）
- §6.1 Registry-mediated trust（实现侧，B 项）
- §6.2 Key rotation（部分由 discovery 结构向量覆盖，运维语义 B 项）
- §6.3 Revocation propagation（fail-closed 判定面有 revocation 向量，传播运维 B 项）
- §6.4 Credential lifecycle（实现侧，B 项）
- §6.5 Delegation-chain verification（链场景未模拟，B 项）
- §6.6 Fail-closed verification（判定面有撤销 fail-closed 向量；网络层不可达属 live/B 项）
- §6.7 Revocation checking（撤销判定面已有向量；消费侧展示属 B 项）

## 机器强制（L2，防"可被误读为绿"的路径）

- **parity 三断言**：验证器 rc≠0 / verdicts 为空 / 判卷集合不等或 != fixtures 实有——任一 → 红
  （堵死"什么都没验却报全部通过"的假绿路径）
- **跨仓版本一致性**（check_spec_version.py）：规范仓库头部版本 == conformance.json spec.version，
  不一致即红——conformance 验证的必须是人读的那份规范
- **规范→向量反向覆盖**（check_spec_coverage.py）：规范含 MUST/SHOULD 的条款区块必须映射到
  向量（fixtures spec.section）或 notCovered 声明，否则红——不允许"规范有要求但既无向量也无声明"
- 拉取规范依赖网络（20s 超时 + 失败 exit 1，fail-closed 不放行）

## schema 与命名空间（A2 澄清）

- `conformance.json` / `fixtures/*.json` 的 `$schema` 指向**仓库内 `schemas/`**（raw.githubusercontent URL，
  可解析非死链）——历史曾指向 `cha2a.org/schemas/*`（从未部署，HTTP 000，已修正）。
- `https://cha2a.org/predicate/*`（evidence `predicateType` 的命名空间标识）是**规范约定 URI**
  （标识符非获取 URL），随域名部署后可解析；作为标识不属死引用。

## 纪律

- 所有密钥 TEST-ONLY（vectors/，标注，绝不用于生产）
- 单验证器阶段不声称"双实现验证"——本套件已双实现互锁（Python+Node）
- 改向量必须重生成 MANIFEST；声称计数必须等于 fixture 实有；notCovered 条数与 conformance.json 一致
