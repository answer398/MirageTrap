<template>
  <div class="console-page">
    <div class="console-shell">
      <nav class="tab-row">
        <button
          v-for="item in tabs"
          :key="item.key"
          type="button"
          class="tab-btn"
          :class="{ active: activeTab === item.key }"
          @click="switchTab(item.key)"
        >
          {{ item.label }}
        </button>
      </nav>

      <section v-if="activeTab === 'attacks'" class="attack-stage">
        <article class="card attack-stage-card">
          <header class="section-head attack-card-head attack-stage-head">
            <div>
              <h2>攻击事件工作台</h2>
              <p class="section-note">筛选、浏览与处置统一收进一张主表，详情改为悬浮工作窗。</p>
            </div>
            <div class="attack-toolbar">
              <span class="result-pill">{{ attackSummaryText }}</span>
              <label class="attack-toolbar-field attack-toolbar-page-size">
                <span>每页</span>
                <select
                  :value="attackQuery.page_size"
                  :disabled="attackListLoading"
                  @change="setAttackPageSize($event.target.value)"
                >
                  <option v-for="size in attackPageSizeOptions" :key="size" :value="size">
                    {{ size }}
                  </option>
                </select>
              </label>
              <button class="btn mini" type="button" @click="submitAttackFilters" :disabled="attackListLoading">
                查询
              </button>
              <button class="btn ghost mini" type="button" @click="resetAttackFilters" :disabled="attackListLoading">
                重置
              </button>
              <button
                class="btn ghost danger mini"
                type="button"
                :disabled="!hasAttackSelections || attackMutating"
                @click="deleteSelectedAttacks"
              >
                {{ hasAttackSelections ? `批量删除（${fmtNum(selectedAttackCount)}）` : "批量删除" }}
              </button>
              <button
                class="btn ghost mini"
                type="button"
                :disabled="attackListLoading || !canExportAttacks || attackExporting"
                @click="promptExportAttacks"
              >
                导出 CSV
              </button>
            </div>
          </header>

          <div class="attack-filter-panel attack-stage-toolbar">
            <div class="attack-time-row">
              <div class="attack-time-presets">
                <button
                  v-for="item in attackTimePresets"
                  :key="item.key"
                  type="button"
                  class="time-range-btn"
                  :class="{ active: attackQuery.time_preset === item.key }"
                  :disabled="attackListLoading"
                  @click="setAttackTimePreset(item.key)"
                >
                  {{ item.label }}
                </button>
              </div>

              <div class="attack-time-fields">
                <label class="attack-inline-field attack-time-field">
                  <span>开始时间</span>
                  <input
                    v-model="attackQuery.start_time"
                    type="datetime-local"
                    @change="markAttackTimeCustom"
                  />
                </label>
                <label class="attack-inline-field attack-time-field">
                  <span>结束时间</span>
                  <input
                    v-model="attackQuery.end_time"
                    type="datetime-local"
                    @change="markAttackTimeCustom"
                  />
                </label>
              </div>
            </div>

            <form class="attack-filter-form-shell" @submit.prevent="submitAttackFilters">
              <div class="attack-primary-filter-row">
                <label class="attack-inline-field">
                  <span>蜜罐实例</span>
                  <select v-model="attackQuery.honeypot_id">
                    <option value="">全部</option>
                    <option v-for="item in attackHoneypotOptions" :key="item.value" :value="item.value">
                      {{ item.label }}
                    </option>
                  </select>
                </label>
                <label class="attack-inline-field">
                  <span>事件类型</span>
                  <select v-model="attackQuery.event_type">
                    <option value="">全部</option>
                    <option v-for="item in attackEventTypeOptions" :key="item.value" :value="item.value">
                      {{ item.label }}
                    </option>
                  </select>
                </label>
                <label class="attack-inline-field">
                  <span>风险等级</span>
                  <select v-model="attackQuery.risk_level">
                    <option value="">全部</option>
                    <option value="low">低</option>
                    <option value="medium">中</option>
                    <option value="high">高</option>
                    <option value="critical">严重</option>
                  </select>
                </label>
                <button
                  class="btn ghost mini attack-advanced-toggle"
                  type="button"
                  :class="{ active: attackAdvancedFiltersOpen }"
                  @click="toggleAttackAdvancedFilters"
                >
                  {{ attackAdvancedFiltersOpen ? "收起详细检索" : "详细检索" }}
                </button>
              </div>

              <div v-if="attackAdvancedFiltersOpen" class="attack-advanced-filter-row">
                <label class="attack-inline-field">
                  <span>来源 IP</span>
                  <input v-model.trim="attackQuery.source_ip" type="text" placeholder="198.51.100.10" />
                </label>
                <label class="attack-inline-field">
                  <span>Session ID</span>
                  <input v-model.trim="attackQuery.session_id" type="text" placeholder="sess_xxx" />
                </label>
                <label class="attack-inline-field">
                  <span>关键词</span>
                  <input
                    v-model.trim="attackQuery.keyword"
                    type="text"
                    placeholder="路径 / 参数 / Body / 国家 / ASN"
                  />
                </label>
              </div>
            </form>

            <div class="attack-stage-meta">
              <div v-if="activeAttackFilters.length" class="filter-chip-row attack-filter-chip-row">
                <button
                  v-for="item in activeAttackFilters"
                  :key="item.key"
                  type="button"
                  class="filter-chip"
                  :disabled="attackListLoading"
                  @click="clearAttackFilter(item.key)"
                >
                  <span>{{ item.label }}</span>
                  <strong>×</strong>
                </button>
              </div>

              <p v-if="attackErrorText" class="inline-error">{{ attackErrorText }}</p>
            </div>
          </div>

          <div class="table-scroll attack-table-scroll">
            <table class="table attack-table attack-grid-table">
              <thead>
                <tr>
                  <th class="select-col">
                    <input
                      class="select-checkbox"
                      :class="{ indeterminate: hasAttackSelections && !allAttacksSelectedOnPage }"
                      type="checkbox"
                      :checked="allAttacksSelectedOnPage"
                      :disabled="attackListLoading || attacks.items.length === 0"
                      @change="toggleAllAttackSelections"
                    />
                  </th>
                  <th class="time-col">时间</th>
                  <th class="source-col">来源</th>
                  <th class="target-col">目标</th>
                  <th class="type-col">类型</th>
                  <th class="risk-col">风险</th>
                  <th class="session-col">会话 / 实例</th>
                  <th class="action-col">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-if="attackListLoading">
                  <td colspan="8" class="empty">正在加载攻击事件...</td>
                </tr>
                <template v-else>
                  <tr
                    v-for="item in attacks.items"
                    :key="item.id"
                    class="attack-table-row"
                    :class="{ selected: selectedAttack && selectedAttack.id === item.id }"
                  >
                    <td class="select-col">
                      <input
                        class="select-checkbox"
                        type="checkbox"
                        :checked="isAttackSelected(item.id)"
                        :disabled="attackMutating"
                        @change="toggleAttackSelection(item.id)"
                      />
                    </td>
                    <td class="time-col">
                      <span class="inline-text mono-text" :title="`${dateText(item.created_at)} · #${item.id}`">
                        {{ dateText(item.created_at) }} · #{{ item.id }}
                      </span>
                    </td>
                    <td class="source-col">
                      <span
                        class="inline-text"
                        :title="`${item.source_ip || '-'} / ${item.country || '未知国家'}`"
                      >
                        {{ item.source_ip || "-" }} / {{ item.country || "未知国家" }}
                      </span>
                    </td>
                    <td class="target-col" :title="item.request_preview || item.request_path || '/'">
                      <div class="target-line target-line-compact">
                        <span class="method-pill">{{ formatMethod(item.request_method) }}</span>
                        <strong class="path-text">{{ item.request_path || "/" }}</strong>
                      </div>
                    </td>
                    <td class="type-col">
                      <strong class="inline-text type-text" :title="typeLabel(item.event_type)">
                        {{ typeLabel(item.event_type) }}
                      </strong>
                    </td>
                    <td class="risk-col">
                      <span class="risk-badge" :class="riskTone(item.risk_level)">
                        {{ riskLabel(item.risk_level) }} / {{ item.risk_score ?? "-" }}
                      </span>
                    </td>
                    <td class="session-col">
                      <span
                        class="inline-text mono-text"
                        :title="`${item.session_id || '-'} / ${item.honeypot_id || '-'}`"
                      >
                        {{ item.session_id || "-" }} / {{ item.honeypot_id || "-" }}
                      </span>
                    </td>
                    <td class="action-col">
                      <div class="attack-row-actions">
                        <button
                          class="btn ghost mini"
                          type="button"
                          :disabled="attackMutating"
                          @click="openAttackDetail(item.id)"
                        >
                          详情
                        </button>
                        <button
                          class="btn ghost danger mini"
                          type="button"
                          :disabled="attackMutating"
                          @click="deleteAttack(item.id)"
                        >
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                  <tr v-if="attacks.items.length === 0">
                    <td colspan="8" class="empty">暂无数据</td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>

          <footer class="attack-list-foot">
            <span class="muted-text">本页 {{ attacks.items.length || 0 }} 条</span>
            <div class="pagination">
              <button
                class="page-btn"
                type="button"
                :disabled="attackListLoading || attacks.page <= 1"
                @click="changeAttackPage(attacks.page - 1)"
              >
                上一页
              </button>
              <button
                v-for="page in attackPageNumbers"
                :key="page"
                class="page-btn"
                :class="{ active: page === attacks.page }"
                type="button"
                :disabled="attackListLoading"
                @click="changeAttackPage(page)"
              >
                {{ page }}
              </button>
              <button
                class="page-btn"
                type="button"
                :disabled="attackListLoading || attacks.page >= attackPageCount"
                @click="changeAttackPage(attacks.page + 1)"
              >
                下一页
              </button>
            </div>
          </footer>
        </article>
      </section>

      <section v-if="activeTab === 'replay'" class="replay-layout">
        <article class="card replay-stage-card">
          <header class="section-head replay-stage-head">
            <div>
              <h2>回放导出工作台</h2>
              <p class="section-note">只保留检索、会话轨道、时间线主表；证据和详情改为按需出现。</p>
            </div>
          </header>

          <div class="replay-command-strip replay-stage-toolbar">
            <form class="replay-command-row" @submit.prevent="submitReplayCommand">
              <label class="replay-query-field">
                <span>来源 IP</span>
                <input v-model.trim="replaySourceIp" type="text" placeholder="198.51.100.10" />
              </label>
              <label class="replay-query-field">
                <span>Session ID</span>
                <input v-model.trim="replaySessionId" type="text" placeholder="sess_xxx" />
              </label>
              <button class="btn mini" type="submit" :disabled="replaySourceLoading || replayTimelineLoading">
                查询
              </button>
              <button class="btn ghost mini" type="button" @click="resetReplayWorkbench">
                重置
              </button>
              <button
                class="btn ghost mini"
                type="button"
                :disabled="!replaySessionId || replayTimelineLoading"
                @click="exportEvidence('json')"
              >
                导出 JSON
              </button>
              <button
                class="btn ghost mini"
                type="button"
                :disabled="!replaySessionId || replayTimelineLoading"
                @click="exportEvidence('pcap')"
              >
                导出 PCAP
              </button>
            </form>
            <p v-if="replayByIp || replayTimeline || activeReplaySession" class="replay-context-line muted-text">
              来源 {{ activeReplaySession?.source_ip || replayByIp?.source_ip || replayTimeline?.session?.source_ip || "-" }}
              · 会话 {{ replaySessionId || "-" }}
              · 事件 {{ fmtNum(replayTimeline?.event_count || replayByIp?.total_events || 0) }}
              · 文件 {{ fmtNum(evidenceData?.stats?.file_count || 0) }}
            </p>

            <p v-if="replayErrorText" class="inline-error">{{ replayErrorText }}</p>
            <p v-if="replayTimelineErrorText && replayTimelineErrorText !== replayErrorText" class="inline-error">
              {{ replayTimelineErrorText }}
            </p>
          </div>

          <div class="replay-stage-body">
            <aside class="replay-session-rail">
              <header class="replay-pane-head">
                <h3>会话</h3>
                <span class="muted-text">最近 {{ fmtNum(replaySessions.length || (activeReplaySession ? 1 : 0)) }} 个</span>
              </header>
              <div v-if="replaySourceLoading" class="empty-state detail-empty">正在加载来源会话...</div>
              <div v-else-if="replaySessions.length" class="session-rail-list">
                <button
                  v-for="session in replaySessions"
                  :key="session.session_id"
                  type="button"
                  class="session-rail-item"
                  :class="{ active: session.session_id === replaySessionId }"
                  @click="selectReplaySession(session.session_id)"
                >
                  <div class="session-rail-top">
                    <strong>{{ session.session_id }}</strong>
                    <span class="risk-badge" :class="riskTone(session.risk_level)">
                      {{ riskLabel(session.risk_level) }}
                    </span>
                  </div>
                  <div class="session-rail-meta">
                    <span>{{ fmtNum(session.event_count) }} 条事件</span>
                    <span>{{ dateText(session.end_time) }}</span>
                  </div>
                </button>
              </div>
              <div v-else-if="activeReplaySession" class="session-rail-list">
                <button type="button" class="session-rail-item active">
                  <div class="session-rail-top">
                    <strong>{{ activeReplaySession.session_id || "-" }}</strong>
                    <span class="risk-badge" :class="riskTone(activeReplaySession.risk_level)">
                      {{ riskLabel(activeReplaySession.risk_level) }}
                    </span>
                  </div>
                  <div class="session-rail-meta">
                    <span>{{ fmtNum(replayTimeline?.event_count || 0) }} 条事件</span>
                    <span>{{ dateText(activeReplaySession.end_time) }}</span>
                  </div>
                </button>
              </div>
              <div v-else class="empty-state detail-empty">输入来源 IP 后查看会话。</div>
            </aside>

            <section class="replay-main-panel">
              <header class="replay-pane-head replay-main-head">
                <div>
                  <h3>时间线</h3>
                  <p class="section-note">主体只保留事件主表，用于快速筛查当前会话的整体攻击情况。</p>
                </div>
              </header>

              <div class="replay-filter-row replay-filter-row-minimal">
                <label class="inline-select">
                  类型
                  <select v-model="replayFilters.event_type">
                    <option value="">全部</option>
                    <option v-for="item in replayTimelineEventTypeOptions" :key="item.value" :value="item.value">
                      {{ item.label }}
                    </option>
                  </select>
                </label>
                <label class="inline-select">
                  风险
                  <select v-model="replayFilters.risk_level">
                    <option value="">全部</option>
                    <option value="low">低</option>
                    <option value="medium">中</option>
                    <option value="high">高</option>
                    <option value="critical">严重</option>
                  </select>
                </label>
                <label class="replay-filter-field">
                  关键词
                  <input v-model.trim="replayFilters.keyword" type="text" placeholder="路径 / 参数 / Body / 规则" />
                </label>
                <button
                  class="btn ghost mini"
                  type="button"
                  :disabled="!hasActiveReplayFilters"
                  @click="resetReplayFilters"
                >
                  清空
                </button>
                <button
                  class="btn ghost mini"
                  type="button"
                  :disabled="!activeReplaySession"
                  @click="jumpToAttackContext({ session: activeReplaySession })"
                >
                  定位攻击
                </button>
              </div>

              <div v-if="replayTimelineLoading" class="empty-state detail-empty">正在加载会话时间线与证据...</div>
              <template v-else-if="replayTimeline">
                <div class="table-scroll replay-event-table-scroll">
                  <table class="table replay-event-table">
                    <thead>
                      <tr>
                        <th class="replay-time-col">时间</th>
                        <th class="replay-target-col">目标</th>
                        <th class="replay-risk-col">风险 / 类型</th>
                        <th class="replay-summary-col">摘要</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="item in filteredReplayTimeline"
                        :key="item.event_id"
                        class="replay-event-row"
                      >
                        <td class="replay-time-col">
                          <span class="inline-text mono-text" :title="`${dateText(item.time)} · #${item.event_id}`">
                            {{ dateText(item.time) }} · #{{ item.event_id }}
                          </span>
                        </td>
                        <td class="replay-target-col" :title="item.request_preview || item.request?.path || '/'">
                          <div class="target-line target-line-compact">
                            <span class="method-pill">{{ formatMethod(item.request?.method) }}</span>
                            <strong class="path-text">{{ item.request?.path || "/" }}</strong>
                          </div>
                        </td>
                        <td class="replay-risk-col">
                          <div class="replay-risk-line">
                            <span class="risk-badge" :class="riskTone(item.risk_level)">
                              {{ riskLabel(item.risk_level) }} / {{ item.risk_score ?? "-" }}
                            </span>
                            <strong class="type-text replay-type-inline" :title="typeLabel(item.event_type)">
                              {{ typeLabel(item.event_type) }}
                            </strong>
                          </div>
                        </td>
                        <td class="replay-summary-col">
                          <span class="inline-text" :title="item.request_preview || '-'">
                            {{ item.request_preview || "-" }}
                          </span>
                        </td>
                      </tr>
                      <tr v-if="!filteredReplayTimeline.length">
                        <td colspan="4" class="empty">当前筛选条件下暂无时间线数据</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </template>
              <div v-else class="empty-state detail-empty">输入来源 IP 或 Session ID 后查看时间线。</div>
            </section>
          </div>

          <div class="replay-drawer-shell">
            <button
              class="replay-drawer-toggle"
              type="button"
              :class="{ active: replayEvidenceDrawerOpen }"
              :disabled="!replaySessionId && !(evidenceData?.files || []).length"
              @click="toggleReplayEvidenceDrawer"
            >
              {{ replayEvidenceDrawerOpen ? "收起证据记录" : "展开证据记录" }}
            </button>

            <section v-if="replayEvidenceDrawerOpen" class="replay-evidence-drawer">
              <header class="section-head replay-drawer-head">
                <div>
                  <h3>证据记录</h3>
                  <p class="section-note">只保留文件列表、下载和完整性校验。</p>
                </div>
                <span class="result-pill">{{ fmtNum(evidenceData?.stats?.file_count || 0) }} 份文件</span>
              </header>
              <ul class="stack-list evidence-file-list">
                <li v-for="item in evidenceData?.files || []" :key="item.id">
                  <div class="cell-stack">
                    <strong>#{{ item.id }} {{ item.file_type }}</strong>
                    <span class="muted-text">{{ item.created_at ? dateText(item.created_at) : "-" }}</span>
                    <span class="muted-text">{{ formatBytes(item.size) }} · sha256 {{ shortHash(item.sha256) }}</span>
                    <span
                      v-if="evidenceVerifyText(item.id)"
                      class="verify-chip"
                      :class="{ failed: isEvidenceVerifyFailed(item.id) }"
                    >
                      {{ evidenceVerifyText(item.id) }}
                    </span>
                  </div>
                  <div class="action-cluster">
                    <button class="btn mini" type="button" @click="downloadFile(item.id)">下载</button>
                    <button
                      class="btn ghost mini"
                      type="button"
                      :disabled="isEvidenceVerifying(item.id)"
                      @click="verifyEvidenceFile(item.id)"
                    >
                      {{ isEvidenceVerifying(item.id) ? "校验中" : "校验完整性" }}
                    </button>
                  </div>
                </li>
                <li v-if="!(evidenceData?.files || []).length" class="empty-line">暂无导出文件</li>
              </ul>
            </section>
          </div>
        </article>
      </section>

      <section v-if="activeTab === 'honeypots'" class="honeypot-layout">
        <article class="card honeypot-stage-card">
          <header class="section-head honeypot-stage-head">
            <div>
              <h2>蜜罐管理工作台</h2>
              <p class="section-note">把筛选、实例列表与详情统一收进一张主卡，新建实例按需展开。</p>
            </div>
          </header>

          <div class="honeypot-command-strip">
            <div class="attack-toolbar honeypot-toolbar">
              <span class="result-pill">{{ honeypotSummaryText }}</span>
              <button class="btn mini" type="button" @click="loadHoneypots" :disabled="honeypotBusy">
                刷新列表
              </button>
              <button class="btn ghost mini" type="button" @click="loadHoneypotCatalog" :disabled="honeypotBusy">
                刷新镜像目录
              </button>
              <button
                class="btn ghost mini"
                type="button"
                :class="{ active: honeypotCreatePanelOpen }"
                @click="toggleHoneypotCreatePanel"
              >
                {{ honeypotCreatePanelOpen ? "收起新建" : "新建实例" }}
              </button>
            </div>

            <div class="honeypot-filter-row honeypot-filter-row-compact">
              <label class="inline-select">
                运行状态
                <select v-model="honeypotQuery.runtime_status">
                  <option value="">全部</option>
                  <option value="running">运行中</option>
                  <option value="stopped">已停止</option>
                  <option value="exited">已退出</option>
                  <option value="missing">容器缺失</option>
                </select>
              </label>
              <label class="inline-select">
                心跳状态
                <select v-model="honeypotQuery.heartbeat_state">
                  <option value="">全部</option>
                  <option value="online">在线</option>
                  <option value="stale">滞后</option>
                  <option value="offline">离线</option>
                  <option value="unknown">未知</option>
                </select>
              </label>
              <label class="honeypot-filter-field">
                关键词
                <input
                  v-model.trim="honeypotQuery.keyword"
                  type="text"
                  placeholder="名称 / ID / 容器 / 端口 / 镜像"
                />
              </label>
              <button
                class="time-range-btn"
                type="button"
                :class="{ active: honeypotQuery.only_attention }"
                @click="honeypotQuery.only_attention = !honeypotQuery.only_attention"
              >
                仅看异常
              </button>
              <button
                class="btn ghost mini"
                type="button"
                :disabled="!hasActiveHoneypotFilters"
                @click="resetHoneypotFilters"
              >
                清空
              </button>
            </div>

            <p v-if="honeypotActionText" class="inline-success">{{ honeypotActionText }}</p>
            <p v-if="honeypotErrorText" class="inline-error">{{ honeypotErrorText }}</p>

            <section v-if="honeypotCreatePanelOpen" class="honeypot-create-panel">
              <header class="honeypot-pane-head honeypot-create-head">
                <div>
                  <h3>新建实例</h3>
                  <p class="section-note">默认收起，避免创建表单长期占据管理视图。</p>
                </div>
              </header>

              <form class="honeypot-create-form" @submit.prevent="createHoneypot">
                <label>
                  蜜罐名称
                  <input v-model.trim="honeypotForm.name" type="text" placeholder="portal-decoy-01" />
                </label>
                <label>
                  镜像枚举
                  <select v-model="honeypotForm.image_key" @change="applyHoneypotCatalogPreset">
                    <option v-for="item in honeypotCatalog.items" :key="item.key" :value="item.key">
                      {{ item.label }}
                    </option>
                  </select>
                </label>
                <label>
                  映射端口
                  <input v-model.number="honeypotForm.exposed_port" type="number" min="1" max="65535" />
                </label>
                <div class="action-cluster honeypot-create-actions">
                  <button class="btn mini" type="submit" :disabled="honeypotBusy">
                    创建实例
                  </button>
                  <button class="btn ghost mini" type="button" @click="toggleHoneypotCreatePanel">
                    收起
                  </button>
                </div>
              </form>

              <p v-if="selectedHoneypotCatalog" class="honeypot-template-line muted-text">
                模板 {{ selectedHoneypotCatalog.label }} · 镜像 {{ selectedHoneypotCatalog.image_name }}
                · 默认映射 {{ selectedHoneypotCatalog.default_exposed_port || "-" }}
                · {{ selectedHoneypotCatalog.description || "未配置模板说明" }}
              </p>
            </section>
          </div>

          <div class="honeypot-stage-body">
            <aside class="honeypot-instance-rail">
              <header class="honeypot-pane-head">
                <h3>实例</h3>
                <span class="muted-text">{{ fmtNum(filteredHoneypots.length) }} 个</span>
              </header>

              <div v-if="honeypotListLoading" class="empty-state detail-empty">正在加载蜜罐实例...</div>
              <div v-else-if="filteredHoneypots.length" class="honeypot-rail-list">
                <button
                  v-for="item in filteredHoneypots"
                  :key="item.id"
                  type="button"
                  class="honeypot-rail-item"
                  :class="{ active: selectedHoneypotId === item.id, attention: honeypotNeedsAttention(item) }"
                  @click="selectHoneypot(item.id)"
                >
                  <div class="honeypot-rail-top">
                    <strong>{{ item.name }}</strong>
                    <span class="status-pill" :class="honeypotRuntimeTone(item)">
                      {{ runtimeStatusLabel(item.runtime_status) }}
                    </span>
                  </div>
                  <div class="honeypot-rail-meta">
                    <span>{{ item.honeypot_id }}</span>
                    <span>{{ honeypotEndpoint(item) }}</span>
                    <span>{{ heartbeatStatusLabel(item.heartbeat_state) }} · {{ honeypotAttentionText(item) }}</span>
                  </div>
                </button>
              </div>
              <div v-else class="empty-state detail-empty">当前筛选条件下暂无蜜罐实例。</div>
            </aside>

            <section class="honeypot-detail-panel">
              <template v-if="selectedHoneypot">
                <div class="detail-hero honeypot-detail-hero">
                  <div class="detail-kicker">
                    <span class="status-pill" :class="honeypotRuntimeTone(selectedHoneypot)">
                      {{ runtimeStatusLabel(selectedHoneypot.runtime_status) }}
                    </span>
                    <span class="status-pill" :class="honeypotHeartbeatTone(selectedHoneypot)">
                      {{ heartbeatStatusLabel(selectedHoneypot.heartbeat_state) }}
                    </span>
                    <span v-if="honeypotNeedsAttention(selectedHoneypot)" class="type-badge">
                      {{ honeypotAttentionText(selectedHoneypot) }}
                    </span>
                  </div>
                  <h3 class="detail-title">{{ selectedHoneypot.name }}</h3>
                  <p class="detail-preview">
                    {{ honeypotEndpoint(selectedHoneypot) }} · {{ selectedHoneypot.honeypot_id }}
                    · {{ honeypotImageLabel(selectedHoneypot.image_key) }}
                  </p>
                </div>

                <div class="honeypot-meta-grid">
                  <article class="honeypot-meta-item">
                    <span>容器</span>
                    <strong class="session-id-text">
                      {{ selectedHoneypot.container_name || "-" }} / {{ selectedHoneypot.container_id || "-" }}
                    </strong>
                  </article>
                  <article class="honeypot-meta-item">
                    <span>网络</span>
                    <strong>
                      {{ selectedHoneypot.bind_host || "-" }}:{{ selectedHoneypot.exposed_port || "-" }}
                      -> {{ selectedHoneypot.container_port || "-" }}
                    </strong>
                  </article>
                  <article class="honeypot-meta-item">
                    <span>镜像模板</span>
                    <strong>{{ honeypotImageLabel(selectedHoneypot.image_key) }}</strong>
                  </article>
                  <article class="honeypot-meta-item">
                    <span>最近心跳</span>
                    <strong>{{ dateText(selectedHoneypot.last_heartbeat_at) }}</strong>
                  </article>
                  <article class="honeypot-meta-item">
                    <span>最近同步</span>
                    <strong>{{ dateText(selectedHoneypot.last_runtime_sync_at || selectedHoneypot.updated_at) }}</strong>
                  </article>
                  <article class="honeypot-meta-item">
                    <span>上报来源</span>
                    <strong>{{ selectedHoneypot.last_seen_ip || "-" }}</strong>
                  </article>
                </div>

                <div class="honeypot-detail-sections">
                  <section class="honeypot-detail-section">
                    <h3>当前关注</h3>
                    <pre>{{ selectedHoneypot.last_error || honeypotAttentionText(selectedHoneypot) || "当前无异常告警" }}</pre>
                  </section>

                  <section class="honeypot-detail-section">
                    <h3>运行元信息</h3>
                    <div class="honeypot-meta-grid honeypot-meta-grid-compact">
                      <article class="honeypot-meta-item">
                        <span>期望状态</span>
                        <strong>{{ runtimeStatusLabel(selectedHoneypot.desired_state) }}</strong>
                      </article>
                      <article class="honeypot-meta-item">
                        <span>创建时间</span>
                        <strong>{{ dateText(selectedHoneypot.created_at) }}</strong>
                      </article>
                    </div>
                    <details class="honeypot-runtime-details">
                      <summary>查看运行元数据</summary>
                      <pre>{{ jsonText(selectedHoneypot.runtime_meta || {}) }}</pre>
                    </details>
                  </section>
                </div>

                <div class="attack-toolbar honeypot-stage-actions">
                  <button
                    class="btn mini"
                    type="button"
                    :disabled="!selectedHoneypot?.honeypot_id"
                    @click="jumpToAttackContext({ honeypot: selectedHoneypot })"
                  >
                    查看相关攻击
                  </button>
                  <button
                    class="btn ghost mini"
                    type="button"
                    :disabled="!canReplaySelectedHoneypot"
                    @click="jumpToReplayContext({ honeypot: selectedHoneypot })"
                  >
                    查看相关回放
                  </button>
                  <button
                    class="btn mini"
                    type="button"
                    :disabled="!canStartHoneypot(selectedHoneypot)"
                    @click="startHoneypot(selectedHoneypot.id)"
                  >
                    启动
                  </button>
                  <button
                    class="btn ghost mini"
                    type="button"
                    :disabled="!canStopHoneypot(selectedHoneypot)"
                    @click="stopHoneypot(selectedHoneypot.id)"
                  >
                    停止
                  </button>
                  <button class="btn ghost mini" type="button" :disabled="honeypotBusy" @click="loadHoneypots">
                    刷新状态
                  </button>
                  <button
                    class="btn ghost danger mini"
                    type="button"
                    :disabled="honeypotBusy"
                    @click="deleteHoneypot(selectedHoneypot.id)"
                  >
                    删除
                  </button>
                </div>
              </template>
              <div v-else class="empty-state">请选择左侧一条蜜罐实例查看详情。</div>
            </section>
          </div>
        </article>
      </section>

      <div
        v-if="attackDetailModalOpen"
        class="console-modal-layer attack-detail-layer"
        @click.self="closeAttackDetail"
      >
        <article class="card console-modal attack-detail-modal" @wheel.stop>
          <header class="section-head attack-card-head attack-modal-head">
            <div>
              <h2>攻击详情</h2>
              <p class="section-note">摘要、请求结构、命中规则和关联会话统一在固定工作窗中查看。</p>
            </div>
            <div class="attack-toolbar">
              <span v-if="selectedAttack" class="result-pill">事件 #{{ selectedAttack.id }}</span>
              <button class="btn ghost mini" type="button" @click="closeAttackDetail">关闭</button>
            </div>
          </header>

          <div v-if="attackDetailLoading" class="empty-state modal-body-scroll">正在加载攻击详情...</div>
          <div v-else-if="selectedAttack" class="detail-body detail-workbench modal-body-scroll">
            <div class="detail-hero">
              <div class="detail-kicker">
                <span class="risk-badge" :class="riskTone(selectedAttack.risk_level)">
                  {{ riskLabel(selectedAttack.risk_level) }} / {{ selectedAttack.risk_score ?? "-" }}
                </span>
                <span class="type-badge">{{ typeLabel(selectedAttack.event_type) }}</span>
              </div>
              <h3 class="detail-title">
                {{ formatMethod(selectedAttack.request_method) }} {{ selectedAttack.request_path || "/" }}
              </h3>
              <p class="detail-preview">{{ selectedAttack.request_preview || "暂无摘要" }}</p>
            </div>

            <div class="detail-summary-grid attack-detail-summary-grid">
              <article class="detail-summary-card is-source">
                <span>来源 IP</span>
                <strong>{{ selectedAttack.source_ip || "-" }}</strong>
              </article>
              <article class="detail-summary-card is-region">
                <span>地区</span>
                <strong>{{ selectedAttack.country || "-" }}</strong>
              </article>
              <article class="detail-summary-card is-session">
                <span>会话</span>
                <strong class="session-id-text">{{ selectedAttack.session_id || "-" }}</strong>
              </article>
              <article class="detail-summary-card is-honeypot">
                <span>蜜罐实例</span>
                <strong>{{ selectedAttack.honeypot_id || selectedAttack.honeypot_type || "-" }}</strong>
              </article>
              <article class="detail-summary-card is-rules">
                <span>命中规则</span>
                <strong>{{ (selectedAttack.rule_details || []).length }}</strong>
              </article>
              <article class="detail-summary-card is-time">
                <span>时间</span>
                <strong>{{ dateText(selectedAttack.created_at) }}</strong>
              </article>
            </div>

            <nav class="detail-tab-row" aria-label="攻击详情视图">
              <button
                v-for="item in attackDetailTabs"
                :key="item.key"
                type="button"
                class="detail-tab-btn"
                :class="{ active: attackDetailTab === item.key }"
                @click="attackDetailTab = item.key"
              >
                {{ item.label }}
              </button>
            </nav>

            <section v-if="attackDetailTab === 'summary'" class="detail-pane">
              <div class="detail-pane-grid">
                <div>
                  <h3>请求概览</h3>
                  <pre>{{ jsonText({
                    method: selectedAttack.request?.method,
                    path: selectedAttack.request?.path,
                    query_string: selectedAttack.request?.query_string,
                    params: selectedAttack.request?.params,
                    request_preview: selectedAttack.request_preview,
                  }) }}</pre>
                </div>
                <div>
                  <h3>命中摘要</h3>
                  <div v-if="(selectedAttack.rule_details || []).length" class="rule-list">
                    <article v-for="rule in selectedAttack.rule_details" :key="rule.key || rule.title" class="rule-card">
                      <strong>{{ rule.title || rule.key || "-" }}</strong>
                      <p>{{ rule.description || "未配置规则说明" }}</p>
                    </article>
                  </div>
                  <div v-else class="empty-state detail-empty">未命中高危规则。</div>
                </div>
              </div>
            </section>

            <section v-if="attackDetailTab === 'request'" class="detail-pane">
              <div class="detail-pane-grid">
                <div>
                  <h3>请求结构</h3>
                  <pre>{{ jsonText({
                    method: selectedAttack.request?.method,
                    path: selectedAttack.request?.path,
                    query_string: selectedAttack.request?.query_string,
                    params: selectedAttack.request?.params,
                    headers: selectedAttack.request?.headers,
                  }) }}</pre>
                </div>
                <div>
                  <h3>请求正文</h3>
                  <pre>{{ selectedAttack.request?.body || "-" }}</pre>
                </div>
              </div>
            </section>

            <section v-if="attackDetailTab === 'rules'" class="detail-pane">
              <div v-if="(selectedAttack.rule_details || []).length" class="rule-list">
                <article v-for="rule in selectedAttack.rule_details" :key="rule.key || rule.title" class="rule-card">
                  <strong>{{ rule.title || rule.key || "-" }}</strong>
                  <p>{{ rule.description || "未配置规则说明" }}</p>
                </article>
              </div>
              <div v-else class="empty-state detail-empty">当前事件没有命中高危规则。</div>
            </section>

            <section v-if="attackDetailTab === 'raw'" class="detail-pane">
              <div class="payload-preview-grid">
                <article class="payload-preview-card">
                  <header class="section-head payload-preview-head">
                    <div>
                      <h3>原始请求</h3>
                      <p class="section-note">{{ payloadSizeText(selectedAttack.request?.raw_request) }}</p>
                    </div>
                    <button
                      class="btn ghost mini"
                      type="button"
                      :disabled="!hasPayload(selectedAttack.request?.raw_request)"
                      @click="openAttackPayload('原始请求', selectedAttack.request?.raw_request)"
                    >
                      点击展开
                    </button>
                  </header>
                  <pre class="payload-preview">{{ previewLargeText(selectedAttack.request?.raw_request) }}</pre>
                </article>

                <article class="payload-preview-card">
                  <header class="section-head payload-preview-head">
                    <div>
                      <h3>响应内容</h3>
                      <p class="section-note">{{ payloadSizeText(selectedAttack.response?.body) }}</p>
                    </div>
                    <button
                      class="btn ghost mini"
                      type="button"
                      :disabled="!hasPayload(selectedAttack.response?.body)"
                      @click="openAttackPayload('响应内容', selectedAttack.response?.body)"
                    >
                      点击展开
                    </button>
                  </header>
                  <pre class="payload-preview">{{ previewLargeText(selectedAttack.response?.body) }}</pre>
                </article>
              </div>
            </section>

            <section class="session-workbench">
              <header class="section-head attack-card-head">
                <div>
                  <h3>关联会话</h3>
                  <p class="section-note">按来源 IP 聚合最近会话，可直接查看时间线与证据。</p>
                </div>
                <div class="attack-toolbar" v-if="activeAttackSessionId">
                  <button
                    class="btn ghost mini"
                    type="button"
                    @click="openReplayTabForSession(activeAttackSessionId, selectedAttack.source_ip)"
                  >
                    前往回放页
                  </button>
                  <button
                    class="btn ghost mini"
                    type="button"
                    @click="exportActiveAttackSessionEvidence('json')"
                    :disabled="attackSessionDataLoading"
                  >
                    导出 JSON
                  </button>
                  <button
                    class="btn ghost mini"
                    type="button"
                    @click="exportActiveAttackSessionEvidence('pcap')"
                    :disabled="attackSessionDataLoading"
                  >
                    导出 PCAP
                  </button>
                </div>
              </header>

              <p v-if="attackSessionErrorText" class="inline-error">{{ attackSessionErrorText }}</p>
              <div v-if="attackSessionsLoading" class="empty-state detail-empty">正在加载关联会话...</div>
              <div v-else-if="attackSessions.length" class="session-card-list">
                <button
                  v-for="session in attackSessions"
                  :key="session.session_id"
                  type="button"
                  class="session-card"
                  :class="{ active: session.session_id === activeAttackSessionId }"
                  @click="selectAttackSession(session.session_id)"
                >
                  <div class="session-card-top">
                    <strong>{{ session.session_id }}</strong>
                    <span class="risk-badge" :class="riskTone(session.risk_level)">
                      {{ riskLabel(session.risk_level) }}
                    </span>
                  </div>
                  <div class="session-card-meta">
                    <span>{{ session.honeypot_type || "-" }} · {{ fmtNum(session.event_count) }} 条事件</span>
                    <span>{{ sessionDurationText(session.start_time, session.end_time) }} · {{ dateText(session.end_time) }}</span>
                  </div>
                  <p class="session-card-summary">{{ session.summary || "暂无会话摘要" }}</p>
                </button>
              </div>
              <div v-else class="empty-state detail-empty">当前来源暂无关联会话。</div>

              <p v-if="attackSessionDataErrorText" class="inline-error">{{ attackSessionDataErrorText }}</p>
              <div v-if="attackSessionDataLoading" class="empty-state detail-empty">正在加载会话时间线与证据...</div>
              <div v-else-if="activeAttackSessionId && activeAttackSession" class="session-detail-grid">
                <article class="session-panel">
                  <header class="section-head">
                    <h3>会话时间线</h3>
                    <span class="result-pill">{{ fmtNum(attackSessionTimeline?.event_count || 0) }} 条</span>
                  </header>
                  <ul class="event-feed compact timeline-feed">
                    <li v-for="item in attackSessionTimeline?.timeline || []" :key="item.event_id">
                      <span>{{ dateText(item.time) }}</span>
                      <strong>{{ typeLabel(item.event_type) }}</strong>
                      <em>{{ item.request_preview }}</em>
                    </li>
                    <li v-if="!(attackSessionTimeline?.timeline || []).length" class="empty-line">暂无时间线数据</li>
                  </ul>
                </article>

                <article class="session-panel">
                  <header class="section-head">
                    <h3>证据与导出</h3>
                    <span class="result-pill">{{ fmtNum(attackSessionEvidence?.stats?.file_count || 0) }} 份文件</span>
                  </header>
                  <div class="detail-summary-grid evidence-stats-grid">
                    <article class="detail-summary-card">
                      <span>会话事件</span>
                      <strong>{{ fmtNum(attackSessionEvidence?.stats?.event_count || 0) }}</strong>
                    </article>
                    <article class="detail-summary-card">
                      <span>高危事件</span>
                      <strong>{{ fmtNum(attackSessionEvidence?.stats?.high_risk_event_count || 0) }}</strong>
                    </article>
                    <article class="detail-summary-card">
                      <span>证据文件</span>
                      <strong>{{ fmtNum(attackSessionEvidence?.stats?.file_count || 0) }}</strong>
                    </article>
                  </div>
                  <ul class="stack-list evidence-file-list">
                    <li v-for="item in attackSessionEvidence?.files || []" :key="item.id">
                      <div class="cell-stack">
                        <strong>#{{ item.id }} {{ item.file_type }}</strong>
                        <span class="muted-text">{{ item.created_at ? dateText(item.created_at) : "-" }}</span>
                        <span class="muted-text">{{ formatBytes(item.size) }} · sha256 {{ shortHash(item.sha256) }}</span>
                        <span
                          v-if="evidenceVerifyText(item.id)"
                          class="verify-chip"
                          :class="{ failed: isEvidenceVerifyFailed(item.id) }"
                        >
                          {{ evidenceVerifyText(item.id) }}
                        </span>
                      </div>
                      <div class="action-cluster">
                        <button class="btn mini" type="button" @click="downloadFile(item.id)">下载</button>
                        <button
                          class="btn ghost mini"
                          type="button"
                          :disabled="isEvidenceVerifying(item.id)"
                          @click="verifyEvidenceFile(item.id)"
                        >
                          {{ isEvidenceVerifying(item.id) ? "校验中" : "校验完整性" }}
                        </button>
                      </div>
                    </li>
                    <li v-if="!(attackSessionEvidence?.files || []).length" class="empty-line">暂无导出文件</li>
                  </ul>
                </article>
              </div>
            </section>
          </div>
          <div v-else class="empty-state modal-body-scroll">当前没有可展示的攻击详情。</div>
        </article>
      </div>

      <div
        v-if="attackDeleteModalOpen"
        class="console-modal-layer attack-confirm-layer"
        @click.self="closeAttackDeleteConfirm"
      >
        <article class="card console-modal attack-confirm-modal">
          <header class="section-head attack-card-head">
            <div>
              <h2>确认删除</h2>
              <p class="section-note">删除后不可恢复，请确认本次操作。</p>
            </div>
          </header>
          <p class="modal-copy">{{ attackDeleteConfirmText }}</p>
          <div class="action-cluster modal-actions">
            <button class="btn ghost mini" type="button" :disabled="attackMutating" @click="closeAttackDeleteConfirm">
              取消
            </button>
            <button class="btn danger mini" type="button" :disabled="attackMutating" @click="confirmDeleteAttacks">
              {{ attackMutating ? "删除中" : "确认删除" }}
            </button>
          </div>
        </article>
      </div>

      <div v-if="honeypotStartModalOpen" class="console-modal-layer honeypot-start-layer">
        <article class="card console-modal honeypot-start-modal">
          <header class="section-head attack-card-head">
            <div>
              <h2>蜜罐容器正在启动</h2>
              <p class="section-note">正在创建 Docker 容器、等待服务心跳并同步运行状态，请稍候。</p>
            </div>
          </header>
          <div class="honeypot-start-body">
            <span class="honeypot-start-spinner" aria-hidden="true"></span>
            <div>
              <strong>{{ honeypotStartMessage }}</strong>
              <p class="modal-copy">启动期间实例可能短暂显示为初始化状态，完成后会自动刷新列表。</p>
            </div>
          </div>
        </article>
      </div>

      <div
        v-if="attackExportModalOpen"
        class="console-modal-layer attack-export-layer"
        @click.self="closeAttackExportConfirm"
      >
        <article class="card console-modal attack-confirm-modal">
          <header class="section-head attack-card-head">
            <div>
              <h2>确认导出</h2>
              <p class="section-note">导出内容将以 CSV 文件下载到本地。</p>
            </div>
          </header>
          <p class="modal-copy">{{ attackExportConfirmText }}</p>
          <div class="action-cluster modal-actions">
            <button class="btn ghost mini" type="button" :disabled="attackExporting" @click="closeAttackExportConfirm">
              取消
            </button>
            <button class="btn mini" type="button" :disabled="attackExporting" @click="confirmExportAttacks">
              {{ attackExporting ? "导出中" : "确认导出" }}
            </button>
          </div>
        </article>
      </div>

      <div
        v-if="attackPayloadModalOpen"
        class="console-modal-layer attack-payload-layer"
        @click.self="closeAttackPayload"
      >
        <article class="card console-modal attack-payload-modal" @wheel.stop>
          <header class="section-head attack-card-head">
            <div>
              <h2>{{ attackPayloadTitle }}</h2>
              <p class="section-note">完整内容单独展开，避免主详情窗被超长文本挤压。</p>
            </div>
            <button class="btn ghost mini" type="button" @click="closeAttackPayload">关闭</button>
          </header>
          <pre class="payload-modal-pre">{{ attackPayloadContent || "-" }}</pre>
        </article>
      </div>

      <div
        v-if="replayDetailModalOpen && selectedReplayEvent"
        class="console-modal-layer replay-detail-layer"
        @click.self="closeReplayDetail"
      >
        <article class="card console-modal replay-detail-modal" @wheel.stop>
          <header class="section-head attack-card-head">
            <div>
              <h2>事件详情</h2>
              <p class="section-note">只展开当前事件所需的最小信息，避免再次形成多卡片阅读负担。</p>
            </div>
            <button class="btn ghost mini" type="button" @click="closeReplayDetail">关闭</button>
          </header>

          <div class="detail-body detail-workbench modal-body-scroll replay-detail-body">
            <div class="replay-detail-meta">
              <span>类型 {{ typeLabel(selectedReplayEvent.event_type) }}</span>
              <span>时间 {{ dateText(selectedReplayEvent.time) }}</span>
              <span>风险 {{ riskLabel(selectedReplayEvent.risk_level) }} / {{ selectedReplayEvent.risk_score ?? "-" }}</span>
            </div>
            <div class="replay-detail-meta">
              <span>来源 {{ activeReplaySession?.source_ip || replayTimeline?.session?.source_ip || "-" }}</span>
              <span class="mono-text">会话 {{ replaySessionId || replayTimeline?.session?.session_id || "-" }}</span>
              <span>目标 {{ formatMethod(selectedReplayEvent.request?.method) }} {{ selectedReplayEvent.request?.path || "/" }}</span>
            </div>
            <div class="attack-toolbar replay-detail-actions">
              <button
                class="btn ghost mini"
                type="button"
                :disabled="!activeReplaySession"
                @click="jumpToAttackContext({ session: activeReplaySession })"
              >
                定位攻击
              </button>
              <button
                class="btn ghost mini"
                type="button"
                :disabled="!activeReplaySession?.honeypot_id"
                @click="jumpToHoneypotContext({ session: activeReplaySession })"
              >
                定位蜜罐
              </button>
            </div>

            <div class="detail-pane-grid replay-detail-pane-grid">
              <div>
                <h3>请求结构</h3>
                <pre>{{ jsonText({
                  method: selectedReplayEvent.request?.method,
                  path: selectedReplayEvent.request?.path,
                  query_string: selectedReplayEvent.request?.query_string,
                  params: selectedReplayEvent.request?.params,
                  headers: selectedReplayEvent.request?.headers,
                }) }}</pre>
              </div>
              <article class="payload-preview-card replay-payload-card">
                <header class="section-head payload-preview-head">
                  <div>
                    <h3>请求正文</h3>
                    <p class="section-note">{{ payloadSizeText(selectedReplayEvent.request?.body) }}</p>
                  </div>
                  <button
                    class="btn ghost mini"
                    type="button"
                    :disabled="!hasPayload(selectedReplayEvent.request?.body)"
                    @click="openAttackPayload('会话请求正文', selectedReplayEvent.request?.body)"
                  >
                    点击展开
                  </button>
                </header>
                <pre class="payload-preview">{{ previewLargeText(selectedReplayEvent.request?.body) }}</pre>
              </article>
            </div>

            <div v-if="(selectedReplayEvent.rule_details || []).length" class="rule-list replay-rule-list">
              <article v-for="rule in selectedReplayEvent.rule_details" :key="rule.key || rule.title" class="rule-card">
                <strong>{{ rule.title || rule.key || "-" }}</strong>
                <p>{{ rule.description || "未配置规则说明" }}</p>
              </article>
            </div>
            <div v-else class="empty-state detail-empty">当前事件未命中可展示规则。</div>
          </div>
        </article>
      </div>
    </div>
  </div>
</template>

<script>
import { getDefaultApiBase, toDateTimeText } from "../utils/common";
import { getAuthSession } from "../utils/authSession";
import { requestBlob, requestJson } from "../utils/apiClient";

const DEFAULT_API = getDefaultApiBase(import.meta.env.VITE_API_BASE_URL);
const DEFAULT_USERNAME = String(import.meta.env.VITE_DEFAULT_USERNAME || "admin");

const TYPE_LABELS = {
  web_req: "普通请求",
  web_sqli: "SQL 注入",
  web_xss: "XSS",
  web_path_traversal: "路径遍历",
  web_cmd_exec: "命令执行",
  web_file_upload: "恶意上传",
  web_ssrf: "SSRF",
  web_ssti: "SSTI",
  web_xxe: "XXE",
  web_scan: "恶意扫描",
};

const RISK_LABELS = {
  low: "低",
  medium: "中",
  high: "高",
  critical: "严重",
};

const RISK_PRIORITY = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const ATTACK_TIME_PRESETS = [
  { key: "all", label: "全部" },
  { key: "24h", label: "24H", hours: 24 },
  { key: "72h", label: "72H", hours: 72 },
  { key: "7d", label: "7D", hours: 168 },
  { key: "30d", label: "30D", hours: 720 },
];

const ATTACK_DETAIL_TABS = [
  { key: "summary", label: "摘要" },
  { key: "request", label: "请求" },
  { key: "rules", label: "规则" },
  { key: "raw", label: "原始报文" },
];

const ATTACK_PAGE_SIZE_OPTIONS = [20, 50, 100, 200];

function createDefaultAttackQuery() {
  return {
    source_ip: "",
    honeypot_id: "",
    session_id: "",
    event_type: "",
    risk_level: "",
    honeypot_type: "web",
    keyword: "",
    start_time: "",
    end_time: "",
    sort_by: "created_at",
    sort_dir: "desc",
    time_preset: "all",
    page: 1,
    page_size: 20,
  };
}

function createDefaultHoneypotQuery() {
  return {
    runtime_status: "",
    heartbeat_state: "",
    keyword: "",
    only_attention: false,
  };
}

function padDatePart(value) {
  return String(value).padStart(2, "0");
}

export default {
  data() {
    return {
      tabs: [
        { key: "attacks", label: "攻击事件" },
        { key: "replay", label: "回放导出" },
        { key: "honeypots", label: "蜜罐管理" },
      ],
      activeTab: "attacks",
      apiBase: "",
      token: "",
      username: "",
      nowText: "--",
      lastSyncText: "未同步",
      backendStatusText: "未连接",
      clockTimer: null,

      attackTimePresets: ATTACK_TIME_PRESETS,
      attackDetailTabs: ATTACK_DETAIL_TABS,
      attackPageSizeOptions: ATTACK_PAGE_SIZE_OPTIONS,
      attackQuery: createDefaultAttackQuery(),
      attacks: { items: [], total: 0, page: 1, page_size: 20, pages: 1 },
      selectedAttackIds: [],
      selectedAttack: null,
      attackDetailTab: "summary",
      attackListLoading: false,
      attackDetailLoading: false,
      attackMutating: false,
      attackErrorText: "",
      attackSessions: [],
      attackSessionsLoading: false,
      attackSessionErrorText: "",
      activeAttackSessionId: "",
      attackSessionTimeline: null,
      attackSessionEvidence: null,
      attackSessionDataLoading: false,
      attackSessionDataErrorText: "",
      attackDetailModalOpen: false,
      attackDeleteModalOpen: false,
      attackDeleteTargetIds: [],
      attackExportModalOpen: false,
      attackExportTargetIds: [],
      attackExporting: false,
      attackPayloadModalOpen: false,
      attackPayloadTitle: "",
      attackPayloadContent: "",
      attackAdvancedFiltersOpen: false,

      replaySourceIp: "",
      replaySessionId: "",
      replayByIp: null,
      replaySourceLoading: false,
      replayErrorText: "",
      replayTimeline: null,
      replayTimelineLoading: false,
      replayTimelineErrorText: "",
      selectedReplayEventId: "",
      replayDetailModalOpen: false,
      replayEvidenceDrawerOpen: false,
      replayFilters: {
        event_type: "",
        risk_level: "",
        keyword: "",
      },
      evidenceData: null,
      evidenceVerifyLoadingMap: {},
      evidenceVerifyResults: {},

      honeypotCatalog: { items: [] },
      honeypots: { items: [], total: 0, summary: {} },
      honeypotQuery: createDefaultHoneypotQuery(),
      honeypotForm: {
        name: "",
        image_key: "cn_cms_portal",
        exposed_port: 18080,
      },
      honeypotCreatePanelOpen: false,
      selectedHoneypotId: null,
      honeypotListLoading: false,
      honeypotBusy: false,
      honeypotStartModalOpen: false,
      honeypotStartMessage: "正在启动蜜罐实例...",
      honeypotErrorText: "",
      honeypotActionText: "",
    };
  },
  computed: {
    attackPageCount() {
      return Math.max(Number(this.attacks.pages || 1), 1);
    },
    attackPageNumbers() {
      const current = Math.min(Math.max(Number(this.attacks.page || 1), 1), this.attackPageCount);
      let start = Math.max(1, current - 2);
      let end = Math.min(this.attackPageCount, start + 4);
      start = Math.max(1, end - 4);

      const pages = [];
      for (let page = start; page <= end; page += 1) {
        pages.push(page);
      }
      return pages;
    },
    attackSummaryText() {
      return `共 ${this.fmtNum(this.attacks.total)} 条 · 第 ${this.attacks.page || 1}/${this.attackPageCount} 页`;
    },
    attackDeleteConfirmText() {
      const ids = this.attackDeleteTargetIds || [];
      if (ids.length <= 1) {
        return ids[0] ? `确认删除攻击事件 #${ids[0]}？` : "确认删除当前攻击事件？";
      }
      return `确认批量删除 ${this.fmtNum(ids.length)} 条攻击事件？`;
    },
    attackExportConfirmText() {
      if ((this.attackExportTargetIds || []).length > 0) {
        return `确认导出已选 ${this.fmtNum(this.attackExportTargetIds.length)} 条攻击事件为 CSV？`;
      }
      return `确认导出当前筛选结果 ${this.fmtNum(this.attacks.total || 0)} 条攻击事件为 CSV？`;
    },
    selectedAttackCount() {
      return this.selectedAttackIds.length;
    },
    hasAttackSelections() {
      return this.selectedAttackCount > 0;
    },
    allAttacksSelectedOnPage() {
      return (
        this.attacks.items.length > 0 &&
        this.attacks.items.every((item) => this.selectedAttackIds.includes(item.id))
      );
    },
    attackSelectionText() {
      return `已选 ${this.fmtNum(this.selectedAttackCount)} 条事件`;
    },
    canExportAttacks() {
      return this.hasAttackSelections || Number(this.attacks.total || 0) > 0;
    },
    attackEventTypeOptions() {
      return Object.entries(TYPE_LABELS).map(([value, label]) => ({ value, label }));
    },
    attackHoneypotOptions() {
      return [...(this.honeypots.items || [])]
        .filter((item) => item?.honeypot_id)
        .sort((left, right) =>
          String(left?.name || left?.honeypot_id || "").localeCompare(
            String(right?.name || right?.honeypot_id || ""),
            "zh-CN",
          ),
        )
        .map((item) => ({
          value: item.honeypot_id,
          label: item.name ? `${item.name} / ${item.honeypot_id}` : item.honeypot_id,
        }));
    },
    activeAttackFilters() {
      const filters = [];
      if (this.attackQuery.source_ip) {
        filters.push({ key: "source_ip", label: `来源 ${this.attackQuery.source_ip}` });
      }
      if (this.attackQuery.honeypot_id) {
        filters.push({ key: "honeypot_id", label: `实例 ${this.attackQuery.honeypot_id}` });
      }
      if (this.attackQuery.session_id) {
        filters.push({ key: "session_id", label: `会话 ${this.attackQuery.session_id}` });
      }
      if (this.attackQuery.event_type) {
        filters.push({ key: "event_type", label: `类型 ${this.typeLabel(this.attackQuery.event_type)}` });
      }
      if (this.attackQuery.risk_level) {
        filters.push({ key: "risk_level", label: `风险 ${this.riskLabel(this.attackQuery.risk_level)}` });
      }
      if (this.attackQuery.keyword) {
        filters.push({ key: "keyword", label: `关键词 ${this.attackQuery.keyword}` });
      }

      const preset = this.attackTimePresets.find((item) => item.key === this.attackQuery.time_preset);
      if (preset && preset.key !== "all" && preset.key !== "custom") {
        filters.push({ key: "time_window", label: `时间 ${preset.label}` });
      } else {
        if (this.attackQuery.start_time) {
          filters.push({ key: "start_time", label: `开始 ${this.attackQuery.start_time.replace("T", " ")}` });
        }
        if (this.attackQuery.end_time) {
          filters.push({ key: "end_time", label: `结束 ${this.attackQuery.end_time.replace("T", " ")}` });
        }
      }
      return filters;
    },
    canReplaySelectedHoneypot() {
      return Boolean(
        this.selectedHoneypot &&
        this.selectedHoneypot.honeypot_id &&
        this.activeReplaySession &&
        this.activeReplaySession.honeypot_id === this.selectedHoneypot.honeypot_id &&
        (this.replaySessionId || this.replaySourceIp),
      );
    },
    replaySessions() {
      return this.replayByIp?.sessions || [];
    },
    replayTimelineEventTypeOptions() {
      const seen = new Set();
      return (this.replayTimeline?.timeline || []).reduce((options, item) => {
        const value = String(item?.event_type || "").trim().toLowerCase();
        if (!value || seen.has(value)) {
          return options;
        }
        seen.add(value);
        options.push({ value, label: this.typeLabel(value) });
        return options;
      }, []);
    },
    filteredReplayTimeline() {
      const eventType = String(this.replayFilters.event_type || "").trim().toLowerCase();
      const riskLevel = String(this.replayFilters.risk_level || "").trim().toLowerCase();
      const keyword = String(this.replayFilters.keyword || "").trim().toLowerCase();

      return (this.replayTimeline?.timeline || []).filter((item) => {
        if (eventType && String(item?.event_type || "").trim().toLowerCase() !== eventType) {
          return false;
        }
        if (riskLevel && String(item?.risk_level || "").trim().toLowerCase() !== riskLevel) {
          return false;
        }
        if (!keyword) {
          return true;
        }

        const haystack = [
          item?.request_preview,
          item?.request?.method,
          item?.request?.path,
          item?.request?.query_string,
          item?.request?.body,
          ...(item?.matched_rules || []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(keyword);
      });
    },
    hasActiveReplayFilters() {
      return Boolean(
        this.replayFilters.event_type || this.replayFilters.risk_level || this.replayFilters.keyword,
      );
    },
    activeReplaySession() {
      const fromList = this.replaySessions.find((item) => item.session_id === this.replaySessionId);
      return fromList || this.replayTimeline?.session || this.evidenceData?.session || null;
    },
    selectedReplayEvent() {
      return (
        (this.replayTimeline?.timeline || []).find((item) => item.event_id === this.selectedReplayEventId) || null
      );
    },
    activeAttackSession() {
      return this.attackSessions.find((item) => item.session_id === this.activeAttackSessionId) || null;
    },
    selectedHoneypotCatalog() {
      return (this.honeypotCatalog.items || []).find((item) => item.key === this.honeypotForm.image_key) || null;
    },
    selectedHoneypot() {
      return (this.honeypots.items || []).find((item) => item.id === this.selectedHoneypotId) || null;
    },
    filteredHoneypots() {
      const runtimeStatus = String(this.honeypotQuery.runtime_status || "").trim().toLowerCase();
      const heartbeatState = String(this.honeypotQuery.heartbeat_state || "").trim().toLowerCase();
      const keyword = String(this.honeypotQuery.keyword || "").trim().toLowerCase();
      const onlyAttention = Boolean(this.honeypotQuery.only_attention);

      return [...(this.honeypots.items || [])]
        .filter((item) => {
          if (runtimeStatus && String(item?.runtime_status || "").trim().toLowerCase() !== runtimeStatus) {
            return false;
          }
          if (heartbeatState && String(item?.heartbeat_state || "").trim().toLowerCase() !== heartbeatState) {
            return false;
          }
          if (onlyAttention && !this.honeypotNeedsAttention(item)) {
            return false;
          }
          if (!keyword) {
            return true;
          }

          const haystack = [
            item?.name,
            item?.honeypot_id,
            item?.container_name,
            item?.container_id,
            item?.host_ip,
            item?.image_key,
            item?.image_name,
            item?.honeypot_profile,
            item?.exposed_port,
          ]
            .filter((value) => value !== null && value !== undefined && value !== "")
            .join(" ")
            .toLowerCase();
          return haystack.includes(keyword);
        })
        .sort((left, right) => {
          const attentionGap = Number(this.honeypotNeedsAttention(right)) - Number(this.honeypotNeedsAttention(left));
          if (attentionGap !== 0) {
            return attentionGap;
          }
          return new Date(right.updated_at || right.created_at || 0).getTime() -
            new Date(left.updated_at || left.created_at || 0).getTime();
        });
    },
    honeypotAttentionCount() {
      return (this.honeypots.items || []).filter((item) => this.honeypotNeedsAttention(item)).length;
    },
    honeypotSummaryText() {
      return `共 ${this.fmtNum(this.filteredHoneypots.length)} / ${this.fmtNum(this.honeypots.total || 0)} 个实例 · 关注 ${this.fmtNum(this.honeypotAttentionCount)} 个`;
    },
    activeHoneypotFilters() {
      const filters = [];
      if (this.honeypotQuery.runtime_status) {
        filters.push({
          key: "runtime_status",
          label: `运行 ${this.runtimeStatusLabel(this.honeypotQuery.runtime_status)}`,
        });
      }
      if (this.honeypotQuery.heartbeat_state) {
        filters.push({
          key: "heartbeat_state",
          label: `心跳 ${this.heartbeatStatusLabel(this.honeypotQuery.heartbeat_state)}`,
        });
      }
      if (this.honeypotQuery.keyword) {
        filters.push({ key: "keyword", label: `关键词 ${this.honeypotQuery.keyword}` });
      }
      if (this.honeypotQuery.only_attention) {
        filters.push({ key: "only_attention", label: "仅看异常" });
      }
      return filters;
    },
    hasActiveHoneypotFilters() {
      return this.activeHoneypotFilters.length > 0;
    },
    consolePriorityItems() {
      const entries = new Map();
      const pushItem = (item) => {
        if (!item) {
          return;
        }
        const nextRank = RISK_PRIORITY[item.level] || 0;
        if (nextRank < 2) {
          return;
        }
        const current = entries.get(item.key);
        const currentRank = current ? RISK_PRIORITY[current.level] || 0 : 0;
        if (!current || nextRank > currentRank || (item.pinned && !current.pinned)) {
          entries.set(item.key, item);
        }
      };

      pushItem(this.buildAttackPriorityItem(this.selectedAttack, { pinned: true, prefix: "当前攻击" }));
      (this.attacks.items || [])
        .slice(0, 6)
        .forEach((item) => pushItem(this.buildAttackPriorityItem(item)));

      pushItem(
        this.buildReplayPriorityItem(this.activeReplaySession, {
          pinned: true,
          highRiskCount: this.evidenceData?.stats?.high_risk_event_count || 0,
          prefix: "当前会话",
        }),
      );
      (this.replaySessions || [])
        .slice(0, 6)
        .forEach((item) => pushItem(this.buildReplayPriorityItem(item)));

      if (this.selectedHoneypot) {
        pushItem(this.buildHoneypotPriorityItem(this.selectedHoneypot, { pinned: true, prefix: "当前实例" }));
      }
      (this.filteredHoneypots || [])
        .slice(0, 6)
        .forEach((item) => pushItem(this.buildHoneypotPriorityItem(item)));

      return Array.from(entries.values())
        .sort((left, right) => {
          const rankGap = (RISK_PRIORITY[right.level] || 0) - (RISK_PRIORITY[left.level] || 0);
          if (rankGap !== 0) {
            return rankGap;
          }
          if (left.pinned !== right.pinned) {
            return Number(right.pinned) - Number(left.pinned);
          }
          return new Date(right.time || 0).getTime() - new Date(left.time || 0).getTime();
        })
        .slice(0, 5);
    },
  },
  watch: {
    nowText() {
      this.emitNavState();
    },
    username() {
      this.emitNavState();
    },
    backendStatusText() {
      this.emitNavState();
    },
    lastSyncText() {
      this.emitNavState();
    },
    filteredReplayTimeline(nextTimeline) {
      if (nextTimeline.some((item) => item.event_id === this.selectedReplayEventId)) {
        return;
      }
      this.selectedReplayEventId = nextTimeline[0]?.event_id || "";
      if (!nextTimeline.length) {
        this.replayDetailModalOpen = false;
      }
    },
    selectedReplayEvent(nextEvent) {
      if (!nextEvent) {
        this.replayDetailModalOpen = false;
      }
    },
    filteredHoneypots(nextItems) {
      if (nextItems.some((item) => item.id === this.selectedHoneypotId)) {
        return;
      }
      this.selectedHoneypotId = nextItems[0]?.id || null;
    },
    attackDetailModalOpen() {
      this.syncModalScrollLock();
    },
    attackDeleteModalOpen() {
      this.syncModalScrollLock();
    },
    attackExportModalOpen() {
      this.syncModalScrollLock();
    },
    honeypotStartModalOpen() {
      this.syncModalScrollLock();
    },
    attackPayloadModalOpen() {
      this.syncModalScrollLock();
    },
    replayDetailModalOpen() {
      this.syncModalScrollLock();
    },
  },
  mounted() {
    this.restoreConfig();
    this.startClock();
    this.emitNavState();
    this.syncModalScrollLock();
    window.addEventListener("miragetrap:console-refresh", this.handleConsoleRefresh);
    if (!this.apiBase || !this.token) {
      this.$router.replace({ path: "/login", query: { redirect: "/console" } });
      return;
    }
    this.refreshCurrent();
  },
  beforeUnmount() {
    if (this.clockTimer) {
      window.clearInterval(this.clockTimer);
      this.clockTimer = null;
    }
    this.resetModalScrollLock();
    window.removeEventListener("miragetrap:console-refresh", this.handleConsoleRefresh);
  },
  methods: {
    syncModalScrollLock() {
      if (typeof document === "undefined") {
        return;
      }

      const hasModalOpen =
        this.attackDetailModalOpen ||
        this.attackDeleteModalOpen ||
        this.attackPayloadModalOpen ||
        this.honeypotStartModalOpen ||
        this.replayDetailModalOpen;
      const hasExportModalOpen = this.attackExportModalOpen;
      document.documentElement.style.overflow = hasModalOpen || hasExportModalOpen ? "hidden" : "";
      document.body.style.overflow = hasModalOpen || hasExportModalOpen ? "hidden" : "";
    },
    resetModalScrollLock() {
      if (typeof document === "undefined") {
        return;
      }

      document.documentElement.style.overflow = "";
      document.body.style.overflow = "";
    },
    emitNavState() {
      if (typeof window === "undefined") {
        return;
      }

      window.dispatchEvent(
        new CustomEvent("miragetrap:console-nav-state", {
          detail: {
            nowText: this.nowText,
            username: this.username || DEFAULT_USERNAME,
            backendStatusText: this.backendStatusText,
            lastSyncText: this.lastSyncText,
          },
        }),
      );
    },
    handleConsoleRefresh() {
      this.refreshCurrent();
    },
    fmtNum(value) {
      const num = Number(value || 0);
      return Number.isFinite(num) ? num.toLocaleString("zh-CN") : "0";
    },
    formatBytes(value) {
      const size = Number(value || 0);
      if (!Number.isFinite(size) || size <= 0) {
        return "0 B";
      }
      const units = ["B", "KB", "MB", "GB"];
      let unitIndex = 0;
      let current = size;
      while (current >= 1024 && unitIndex < units.length - 1) {
        current /= 1024;
        unitIndex += 1;
      }
      const digits = current >= 100 || unitIndex === 0 ? 0 : 1;
      return `${current.toFixed(digits)} ${units[unitIndex]}`;
    },
    shortHash(value, length = 12) {
      const text = String(value || "").trim();
      if (!text) {
        return "-";
      }
      return text.length > length ? `${text.slice(0, length)}...` : text;
    },
    formatMethod(value) {
      return String(value || "GET").trim().toUpperCase();
    },
    dateText(value) {
      return toDateTimeText(value);
    },
    jsonText(value) {
      return JSON.stringify(value || {}, null, 2);
    },
    typeLabel(value) {
      return TYPE_LABELS[String(value || "").trim().toLowerCase()] || value || "-";
    },
    riskLabel(value) {
      return RISK_LABELS[String(value || "").trim().toLowerCase()] || value || "-";
    },
    highestRiskLevel(levels = []) {
      return levels.reduce((current, item) => {
        const normalized = String(item || "").trim().toLowerCase() || "low";
        if ((RISK_PRIORITY[normalized] || 0) > (RISK_PRIORITY[current] || 0)) {
          return normalized;
        }
        return current;
      }, "low");
    },
    riskTone(value) {
      return String(value || "").trim().toLowerCase() || "low";
    },
    attackAttentionLevel(item) {
      const normalized = String(item?.risk_level || "").trim().toLowerCase() || "low";
      return RISK_PRIORITY[normalized] ? normalized : "low";
    },
    replayAttentionLevel(session, highRiskCount = 0) {
      const normalized = String(session?.risk_level || "").trim().toLowerCase() || "low";
      if (highRiskCount > 0 && (RISK_PRIORITY[normalized] || 0) < RISK_PRIORITY.high) {
        return "high";
      }
      return RISK_PRIORITY[normalized] ? normalized : "low";
    },
    honeypotAttentionLevel(item) {
      if (!item) {
        return "low";
      }
      const runtimeStatus = String(item.runtime_status || "").trim().toLowerCase();
      const heartbeatState = String(item.heartbeat_state || "").trim().toLowerCase();
      if (item.last_error || runtimeStatus === "missing" || runtimeStatus === "exited") {
        return "critical";
      }
      if (runtimeStatus === "running" && ["stale", "offline"].includes(heartbeatState)) {
        return "high";
      }
      if (runtimeStatus === "running" && heartbeatState === "unknown") {
        return "medium";
      }
      return "low";
    },
    buildAttackPriorityItem(item, { pinned = false, prefix = "" } = {}) {
      if (!item?.id) {
        return null;
      }
      return {
        key: `attack-${item.id}`,
        kind: "attack",
        level: this.attackAttentionLevel(item),
        pinned,
        time: item.created_at,
        title: prefix ? `${prefix} #${item.id}` : `攻击 #${item.id}`,
        summary: [item.source_ip, item.request_preview || item.request_path || "/", item.honeypot_id]
          .filter(Boolean)
          .join(" · "),
        payload: { attack: item, eventId: item.id },
      };
    },
    buildReplayPriorityItem(session, { pinned = false, highRiskCount = 0, prefix = "" } = {}) {
      if (!session?.session_id) {
        return null;
      }
      const riskSuffix = highRiskCount > 0 ? ` · 高危 ${this.fmtNum(highRiskCount)} 条` : "";
      return {
        key: `replay-${session.session_id}`,
        kind: "replay",
        level: this.replayAttentionLevel(session, highRiskCount),
        pinned,
        time: session.end_time || session.start_time,
        title: prefix ? `${prefix} ${session.session_id}` : `会话 ${session.session_id}`,
        summary: `${session.source_ip || "-"} · ${this.fmtNum(session.event_count || 0)} 条事件${riskSuffix}`,
        payload: { session },
      };
    },
    buildHoneypotPriorityItem(item, { pinned = false, prefix = "" } = {}) {
      if (!item?.honeypot_id) {
        return null;
      }
      return {
        key: `honeypot-${item.honeypot_id}`,
        kind: "honeypot",
        level: this.honeypotAttentionLevel(item),
        pinned,
        time: item.updated_at || item.last_runtime_sync_at || item.created_at,
        title: prefix ? `${prefix} ${item.name}` : `实例 ${item.name}`,
        summary: [this.honeypotAttentionText(item), this.honeypotEndpoint(item), item.honeypot_id]
          .filter(Boolean)
          .join(" · "),
        payload: { honeypot: item },
      };
    },
    extractContextFromAttack(attack) {
      return {
        source_ip: attack?.source_ip || "",
        session_id: attack?.session_id || "",
        honeypot_id: attack?.honeypot_id || "",
        honeypot_name: "",
      };
    },
    extractContextFromSession(session) {
      return {
        source_ip: session?.source_ip || "",
        session_id: session?.session_id || "",
        honeypot_id: session?.honeypot_id || "",
        honeypot_name: "",
      };
    },
    extractContextFromHoneypot(item) {
      return {
        source_ip: "",
        session_id: "",
        honeypot_id: item?.honeypot_id || "",
        honeypot_name: item?.name || "",
      };
    },
    async openPriorityItem(item) {
      if (!item) {
        return;
      }
      if (item.kind === "attack") {
        await this.jumpToAttackContext(item.payload);
        return;
      }
      if (item.kind === "replay") {
        await this.jumpToReplayContext(item.payload);
        return;
      }
      await this.jumpToHoneypotContext(item.payload);
    },
    sessionDurationText(startTime, endTime) {
      const start = new Date(startTime);
      const end = new Date(endTime || startTime);
      if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
        return "-";
      }
      const diffMs = Math.max(end.getTime() - start.getTime(), 0);
      const totalSeconds = Math.round(diffMs / 1000);
      if (totalSeconds < 60) {
        return `${totalSeconds}s`;
      }
      const totalMinutes = Math.floor(totalSeconds / 60);
      const seconds = totalSeconds % 60;
      if (totalMinutes < 60) {
        return seconds ? `${totalMinutes}m ${seconds}s` : `${totalMinutes}m`;
      }
      const hours = Math.floor(totalMinutes / 60);
      const minutes = totalMinutes % 60;
      return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
    },
    attackRuleSummary(ruleDetails = [], compact = true) {
      if (!Array.isArray(ruleDetails) || !ruleDetails.length) {
        return "-";
      }
      const labels = ruleDetails
        .map((item) => item?.title || item?.key)
        .filter(Boolean);
      if (!labels.length) {
        return "-";
      }
      if (!compact) {
        return labels.join(" / ");
      }
      const summary = labels.slice(0, 2).join(" / ");
      return labels.length > 2 ? `${summary} 等 ${labels.length} 条` : summary;
    },
    restoreConfig() {
      const session = getAuthSession();
      this.apiBase = session.apiBase || DEFAULT_API;
      this.token = session.token || "";
      this.username = session.username || DEFAULT_USERNAME;
    },
    startClock() {
      const update = () => {
        this.nowText = toDateTimeText(new Date().toISOString());
      };
      update();
      this.clockTimer = window.setInterval(update, 1000);
    },
    async request(path, options = {}) {
      return requestJson({
        apiBase: this.apiBase,
        token: this.token,
        path,
        ...options,
      });
    },
    toApiDateTime(value) {
      if (!value) {
        return "";
      }
      const parsed = new Date(value);
      if (Number.isNaN(parsed.getTime())) {
        return "";
      }
      return parsed.toISOString();
    },
    formatDateTimeLocalInput(date) {
      const value = date instanceof Date ? date : new Date(date);
      if (Number.isNaN(value.getTime())) {
        return "";
      }
      return `${value.getFullYear()}-${padDatePart(value.getMonth() + 1)}-${padDatePart(value.getDate())}T${padDatePart(value.getHours())}:${padDatePart(value.getMinutes())}`;
    },
    markAttackTimeCustom() {
      this.attackQuery.time_preset = "custom";
    },
    setAttackPageSize(value) {
      const nextSize = Number(value);
      if (!ATTACK_PAGE_SIZE_OPTIONS.includes(nextSize) || nextSize === this.attackQuery.page_size) {
        return;
      }
      this.attackQuery.page_size = nextSize;
      this.loadAttacks({ page: 1 });
    },
    toggleAttackAdvancedFilters() {
      this.attackAdvancedFiltersOpen = !this.attackAdvancedFiltersOpen;
    },
    submitAttackFilters() {
      this.loadAttacks({ page: 1 });
    },
    resetAttackFilters() {
      this.attackQuery = createDefaultAttackQuery();
      this.attackAdvancedFiltersOpen = false;
      this.attackErrorText = "";
      this.loadAttacks({ page: 1 });
    },
    async jumpToAttackContext(payload = {}) {
      const nextContext = payload.attack
        ? this.extractContextFromAttack(payload.attack)
        : payload.session
          ? this.extractContextFromSession(payload.session)
          : payload.honeypot
            ? this.extractContextFromHoneypot(payload.honeypot)
            : {
                source_ip: payload.source_ip ? String(payload.source_ip).trim() : "",
                session_id: payload.session_id ? String(payload.session_id).trim() : "",
                honeypot_id: payload.honeypot_id ? String(payload.honeypot_id).trim() : "",
                honeypot_name: payload.honeypot_name ? String(payload.honeypot_name).trim() : "",
              };

      this.attackQuery = {
        ...createDefaultAttackQuery(),
        page_size: this.attackQuery.page_size,
        sort_by: this.attackQuery.sort_by,
        sort_dir: this.attackQuery.sort_dir,
        honeypot_type: this.attackQuery.honeypot_type || "web",
        source_ip: nextContext.source_ip || "",
        session_id: nextContext.session_id || "",
        honeypot_id: nextContext.honeypot_id || "",
      };
      this.attackAdvancedFiltersOpen = Boolean(nextContext.source_ip || nextContext.session_id);

      await this.switchTab("attacks");
      await this.loadAttacks({ page: 1 });

      const targetEventId = payload.eventId || payload.attack?.id;
      if (targetEventId && this.attacks.items.some((item) => item.id === targetEventId)) {
        await this.openAttackDetail(targetEventId);
      }
    },
    async jumpToReplayContext(payload = {}) {
      let nextSourceIp = "";
      let nextSessionId = "";

      if (payload.attack) {
        const nextContext = this.extractContextFromAttack(payload.attack);
        nextSourceIp = nextContext.source_ip;
        nextSessionId = nextContext.session_id;
      } else if (payload.session) {
        const nextContext = this.extractContextFromSession(payload.session);
        nextSourceIp = nextContext.source_ip;
        nextSessionId = nextContext.session_id;
      } else if (payload.honeypot) {
        const currentReplayMatches =
          this.activeReplaySession &&
          this.activeReplaySession.honeypot_id === payload.honeypot.honeypot_id;
        if (currentReplayMatches) {
          nextSourceIp = this.replaySourceIp || this.activeReplaySession.source_ip || "";
          nextSessionId = this.replaySessionId || this.activeReplaySession.session_id || "";
        }
      } else {
        nextSourceIp = payload.source_ip ? String(payload.source_ip).trim() : "";
        nextSessionId = payload.session_id ? String(payload.session_id).trim() : "";
      }

      if (!nextSourceIp && !nextSessionId) {
        return;
      }

      this.resetReplayFilters();
      this.replaySourceIp = nextSourceIp;
      this.replaySessionId = nextSessionId;

      await this.switchTab("replay");
      if (this.replaySourceIp) {
        await this.loadReplayByIp({ preferredSessionId: this.replaySessionId });
      } else if (this.replaySessionId) {
        await this.loadReplayTimeline();
      }
    },
    async jumpToHoneypotContext(payload = {}) {
      const nextHoneypotId = payload.attack
        ? this.extractContextFromAttack(payload.attack).honeypot_id
        : payload.session
          ? this.extractContextFromSession(payload.session).honeypot_id
          : payload.honeypot
            ? this.extractContextFromHoneypot(payload.honeypot).honeypot_id
            : payload.honeypot_id
              ? String(payload.honeypot_id).trim()
              : "";

      if (!nextHoneypotId) {
        return;
      }

      await this.switchTab("honeypots");
      const matched = (this.honeypots.items || []).find((item) => item.honeypot_id === nextHoneypotId);
      if (matched) {
        this.selectedHoneypotId = matched.id;
      }
    },
    setAttackTimePreset(presetKey) {
      const preset = this.attackTimePresets.find((item) => item.key === presetKey);
      if (!preset) {
        return;
      }

      this.attackQuery.time_preset = preset.key;
      if (!preset.hours) {
        this.attackQuery.start_time = "";
        this.attackQuery.end_time = "";
      } else {
        const endTime = new Date();
        const startTime = new Date(endTime.getTime() - preset.hours * 60 * 60 * 1000);
        this.attackQuery.start_time = this.formatDateTimeLocalInput(startTime);
        this.attackQuery.end_time = this.formatDateTimeLocalInput(endTime);
      }
      this.loadAttacks({ page: 1 });
    },
    changeAttackPage(page) {
      const nextPage = Number(page);
      if (!Number.isFinite(nextPage) || nextPage < 1 || nextPage === this.attacks.page) {
        return;
      }
      if (nextPage > this.attackPageCount) {
        return;
      }
      this.loadAttacks({ page: nextPage });
    },
    clearAttackFilter(key) {
      if (key === "time_window") {
        this.attackQuery.start_time = "";
        this.attackQuery.end_time = "";
        this.attackQuery.time_preset = "all";
      } else if (key === "start_time") {
        this.attackQuery.start_time = "";
        this.attackQuery.time_preset = this.attackQuery.end_time ? "custom" : "all";
      } else if (key === "end_time") {
        this.attackQuery.end_time = "";
        this.attackQuery.time_preset = this.attackQuery.start_time ? "custom" : "all";
      } else if (Object.prototype.hasOwnProperty.call(this.attackQuery, key)) {
        this.attackQuery[key] = "";
      }
      this.loadAttacks({ page: 1 });
    },
    promptExportAttacks() {
      if (!this.canExportAttacks || this.attackExporting) {
        return;
      }
      this.attackExportTargetIds = this.normalizeAttackIds(this.selectedAttackIds);
      this.attackExportModalOpen = true;
    },
    closeAttackExportConfirm() {
      if (this.attackExporting) {
        return;
      }
      this.attackExportModalOpen = false;
      this.attackExportTargetIds = [];
    },
    async confirmExportAttacks() {
      const success = await this.exportFilteredAttacks(this.attackExportTargetIds);
      if (success) {
        this.closeAttackExportConfirm();
      }
    },
    async exportFilteredAttacks(eventIds = []) {
      const startTime = this.toApiDateTime(this.attackQuery.start_time);
      const endTime = this.toApiDateTime(this.attackQuery.end_time);
      if (startTime && endTime && new Date(startTime).getTime() > new Date(endTime).getTime()) {
        this.attackErrorText = "开始时间不能晚于结束时间";
        return false;
      }

      const ids = this.normalizeAttackIds(eventIds);
      this.attackErrorText = "";
      this.attackExporting = true;
      try {
        if (ids.length) {
          this.downloadSelectedAttackCsv(ids);
          return true;
        }
        const result = await requestBlob({
          apiBase: this.apiBase,
          token: this.token,
          path: "/api/attacks/export",
          query: {
            ids: ids.length ? ids.join(",") : undefined,
            source_ip: this.attackQuery.source_ip,
            honeypot_id: this.attackQuery.honeypot_id,
            session_id: this.attackQuery.session_id,
            event_type: this.attackQuery.event_type,
            risk_level: this.attackQuery.risk_level,
            honeypot_type: this.attackQuery.honeypot_type,
            keyword: this.attackQuery.keyword,
            start_time: startTime,
            end_time: endTime,
            sort_by: this.attackQuery.sort_by,
            sort_dir: this.attackQuery.sort_dir,
          },
        });
        const url = window.URL.createObjectURL(result.blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = this.resolveFilename(result.contentDisposition, "attacks-export.csv");
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.URL.revokeObjectURL(url);
        return true;
      } catch (error) {
        this.attackErrorText = this.extractErrorMessage(error, "导出攻击事件失败");
        return false;
      } finally {
        this.attackExporting = false;
      }
    },
    downloadSelectedAttackCsv(eventIds) {
      const idSet = new Set(this.normalizeAttackIds(eventIds));
      const items = (this.attacks.items || []).filter((item) => idSet.has(item.id));
      const headers = [
        "id",
        "created_at",
        "source_ip",
        "honeypot_id",
        "country",
        "city",
        "session_id",
        "honeypot_type",
        "event_type",
        "risk_level",
        "risk_score",
        "request_method",
        "request_path",
        "request_preview",
        "matched_rules",
      ];
      const lines = [
        headers.join(","),
        ...items.map((item) =>
          headers
            .map((key) => {
              const value = {
                id: item.id,
                created_at: item.created_at,
                source_ip: item.source_ip,
                honeypot_id: item.honeypot_id || "",
                country: item.country || "",
                city: item.city || "",
                session_id: item.session_id || "",
                honeypot_type: item.honeypot_type || "",
                event_type: item.event_type || "",
                risk_level: item.risk_level || "",
                risk_score: item.risk_score ?? 0,
                request_method: item.request_method || "",
                request_path: item.request_path || "",
                request_preview: item.request_preview || "",
                matched_rules: (item.rule_details || [])
                  .map((rule) => rule.title || rule.key || "")
                  .filter(Boolean)
                  .join(" / "),
              }[key];
              return this.escapeCsvValue(value);
            })
            .join(","),
        ),
      ];

      const blob = new Blob([`\uFEFF${lines.join("\r\n")}`], {
        type: "text/csv;charset=utf-8",
      });
      const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `attacks-selected-${timestamp}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    },
    escapeCsvValue(value) {
      const text = String(value ?? "");
      if (!/[",\r\n]/.test(text)) {
        return text;
      }
      return `"${text.replace(/"/g, '""')}"`;
    },
    isAttackSelected(eventId) {
      return this.selectedAttackIds.includes(eventId);
    },
    toggleAttackSelection(eventId) {
      if (this.isAttackSelected(eventId)) {
        this.selectedAttackIds = this.selectedAttackIds.filter((item) => item !== eventId);
        return;
      }
      this.selectedAttackIds = [...this.selectedAttackIds, eventId];
    },
    toggleAllAttackSelections() {
      if (this.allAttacksSelectedOnPage) {
        this.clearAttackSelection();
        return;
      }
      this.selectedAttackIds = this.attacks.items.map((item) => item.id);
    },
    clearAttackSelection() {
      this.selectedAttackIds = [];
    },
    resetAttackSessionState() {
      this.attackSessions = [];
      this.attackSessionsLoading = false;
      this.attackSessionErrorText = "";
      this.activeAttackSessionId = "";
      this.attackSessionTimeline = null;
      this.attackSessionEvidence = null;
      this.attackSessionDataLoading = false;
      this.attackSessionDataErrorText = "";
    },
    async refreshCurrent() {
      this.backendStatusText = "同步中";
      try {
        await this.request("/api/health/details", { withAuth: false });
        if (this.activeTab === "attacks") {
          await Promise.all([this.loadAttacks(), this.ensureAttackHoneypotOptions()]);
        }
        if (this.activeTab === "replay") {
          if (this.replaySourceIp) {
            await this.loadReplayByIp({ preferredSessionId: this.replaySessionId });
          } else if (this.replaySessionId) {
            await this.loadReplayTimeline();
          }
        }
        if (this.activeTab === "honeypots") {
          await Promise.all([this.loadHoneypotCatalog(), this.loadHoneypots()]);
        }
        this.lastSyncText = toDateTimeText(new Date().toISOString());
        this.backendStatusText = "已连接";
      } catch (error) {
        this.backendStatusText = "获取失败";
        throw error;
      }
    },
    async switchTab(key) {
      if (key !== "attacks") {
        this.closeAttackDetail();
        this.closeAttackDeleteConfirm();
        this.closeAttackExportConfirm();
      }
      if (key !== "replay") {
        this.closeReplayDetail();
        this.replayEvidenceDrawerOpen = false;
      }
      if (key !== "honeypots") {
        this.honeypotCreatePanelOpen = false;
      }
      this.activeTab = key;
      if (key === "attacks") {
        await Promise.all([
          this.ensureAttackHoneypotOptions(),
          this.attacks.items.length === 0 ? this.loadAttacks({ page: 1 }) : Promise.resolve(),
        ]);
      }
      if (key === "replay") {
        if (!this.replayByIp && this.replaySourceIp) {
          await this.loadReplayByIp({ preferredSessionId: this.replaySessionId });
        } else if (!this.replayTimeline && this.replaySessionId) {
          await this.loadReplayTimeline();
        }
      }
      if (key === "honeypots") {
        if (!this.honeypotCatalog.items.length) {
          await this.loadHoneypotCatalog();
        }
        await this.loadHoneypots();
      }
    },
    async loadAttacks({ page = this.attackQuery.page } = {}) {
      const startTime = this.toApiDateTime(this.attackQuery.start_time);
      const endTime = this.toApiDateTime(this.attackQuery.end_time);
      if (startTime && endTime && new Date(startTime).getTime() > new Date(endTime).getTime()) {
        this.attackErrorText = "开始时间不能晚于结束时间";
        return;
      }

      this.attackErrorText = "";
      this.attackListLoading = true;
      this.attackQuery.page = Math.max(Number(page || 1), 1);

      try {
        const data = await this.request("/api/attacks", {
          query: {
            page: this.attackQuery.page,
            page_size: this.attackQuery.page_size,
            source_ip: this.attackQuery.source_ip,
            honeypot_id: this.attackQuery.honeypot_id,
            session_id: this.attackQuery.session_id,
            event_type: this.attackQuery.event_type,
            risk_level: this.attackQuery.risk_level,
            honeypot_type: this.attackQuery.honeypot_type,
            keyword: this.attackQuery.keyword,
            start_time: startTime,
            end_time: endTime,
            sort_by: this.attackQuery.sort_by,
            sort_dir: this.attackQuery.sort_dir,
          },
        });
        this.attacks = {
          items: data.items || [],
          total: data.total || 0,
          page: data.page || this.attackQuery.page,
          page_size: data.page_size || this.attackQuery.page_size,
          pages: data.pages || 1,
        };
        this.selectedAttackIds = this.selectedAttackIds.filter((item) =>
          this.attacks.items.some((attack) => attack.id === item),
        );

        const selectedId = this.selectedAttack?.id;
        const existingRow = this.attacks.items.find((item) => item.id === selectedId);
        if (existingRow) {
          await this.showAttack(existingRow.id, { resetTab: false });
          return;
        }
        if (this.attackDetailModalOpen) {
          this.closeAttackDetail();
        }
        this.selectedAttack = null;
        this.resetAttackSessionState();
      } catch (error) {
        this.attackErrorText = this.extractErrorMessage(error, "加载攻击事件失败");
        throw error;
      } finally {
        this.attackListLoading = false;
      }
    },
    resolveAttackPageAfterDelete(eventIds) {
      const deletedIdSet = new Set(Array.isArray(eventIds) ? eventIds : []);
      const remainingOnPage = this.attacks.items.filter((item) => !deletedIdSet.has(item.id)).length;
      if (remainingOnPage === 0 && Number(this.attacks.page || 1) > 1) {
        return Number(this.attacks.page) - 1;
      }
      return Number(this.attacks.page || 1);
    },
    normalizeAttackIds(eventIds) {
      return Array.from(
        new Set(
          (Array.isArray(eventIds) ? eventIds : [eventIds])
            .map((item) => Number(item))
            .filter((item) => Number.isFinite(item) && item > 0),
        ),
      );
    },
    hasPayload(value) {
      return this.normalizePayloadText(value) !== "-";
    },
    normalizePayloadText(value) {
      if (value === null || value === undefined || value === "") {
        return "-";
      }
      if (typeof value === "string") {
        return value;
      }
      return this.jsonText(value);
    },
    previewLargeText(value, maxLength = 420) {
      const text = this.normalizePayloadText(value);
      if (text === "-" || text.length <= maxLength) {
        return text;
      }
      return `${text.slice(0, maxLength)}\n\n... 点击展开查看全部内容`;
    },
    payloadSizeText(value) {
      const text = this.normalizePayloadText(value);
      if (text === "-") {
        return "无数据";
      }
      return `${this.fmtNum(text.length)} 字符`;
    },
    async openAttackDetail(eventId, { tab = "summary" } = {}) {
      if (!eventId) {
        return;
      }
      this.attackDetailModalOpen = true;
      this.closeAttackPayload();
      this.attackDetailTab = tab;
      this.attackErrorText = "";
      try {
        await this.showAttack(eventId, { resetTab: false });
      } catch (error) {
        this.attackErrorText = this.extractErrorMessage(error, "加载攻击详情失败");
      }
    },
    closeAttackDetail() {
      this.attackDetailModalOpen = false;
      this.closeAttackPayload();
    },
    openAttackPayload(title, content) {
      this.attackPayloadTitle = title || "原始内容";
      this.attackPayloadContent = this.normalizePayloadText(content);
      this.attackPayloadModalOpen = true;
    },
    closeAttackPayload() {
      this.attackPayloadModalOpen = false;
      this.attackPayloadTitle = "";
      this.attackPayloadContent = "";
    },
    deleteAttack(eventId) {
      this.promptDeleteAttacks([eventId]);
    },
    deleteSelectedAttacks() {
      this.promptDeleteAttacks(this.selectedAttackIds);
    },
    promptDeleteAttacks(eventIds) {
      const ids = this.normalizeAttackIds(eventIds);
      if (!ids.length || this.attackMutating) {
        return;
      }
      this.attackDeleteTargetIds = ids;
      this.attackDeleteModalOpen = true;
    },
    closeAttackDeleteConfirm() {
      if (this.attackMutating) {
        return;
      }
      this.attackDeleteModalOpen = false;
      this.attackDeleteTargetIds = [];
    },
    async confirmDeleteAttacks() {
      const ids = [...this.attackDeleteTargetIds];
      if (!ids.length) {
        return;
      }
      const success = await this.deleteAttackBatch(ids);
      if (success) {
        this.closeAttackDeleteConfirm();
      }
    },
    async deleteAttackBatch(eventIds) {
      const ids = this.normalizeAttackIds(eventIds);
      if (!ids.length || this.attackMutating) {
        return false;
      }

      const deletedIdSet = new Set(ids);
      const deletingSelectedAttack = Boolean(this.selectedAttack?.id && deletedIdSet.has(this.selectedAttack.id));
      const nextPage = this.resolveAttackPageAfterDelete(ids);

      this.attackMutating = true;
      this.attackErrorText = "";

      try {
        await this.request("/api/attacks/bulk-delete", {
          method: "POST",
          body: { ids },
        });
        this.selectedAttackIds = this.selectedAttackIds.filter((item) => !deletedIdSet.has(item));
        if (deletingSelectedAttack) {
          this.closeAttackDetail();
          this.selectedAttack = null;
          this.resetAttackSessionState();
        }
        await this.loadAttacks({ page: nextPage });
        return true;
      } catch (error) {
        const rawMessage = this.extractErrorMessage(
          error,
          ids.length === 1 ? "删除攻击事件失败" : "批量删除攻击事件失败",
        );
        if (/HTTP 404|HTTP 405/i.test(rawMessage)) {
          this.attackErrorText = "当前后端进程未加载攻击事件删除接口，请重启后端服务后重试";
          return false;
        }
        this.attackErrorText = this.extractErrorMessage(
          error,
          ids.length === 1 ? "删除攻击事件失败" : "批量删除攻击事件失败",
        );
        return false;
      } finally {
        this.attackMutating = false;
      }
    },
    async showAttack(eventId, { resetTab = true } = {}) {
      this.attackDetailLoading = true;
      try {
        this.selectedAttack = await this.request(`/api/attacks/${eventId}`);
        if (resetTab) {
          this.attackDetailTab = "summary";
        }
        await this.loadAttackSessions(this.selectedAttack.source_ip, this.selectedAttack.session_id);
      } finally {
        this.attackDetailLoading = false;
      }
    },
    async loadAttackSessions(sourceIp, preferredSessionId = "") {
      this.resetAttackSessionState();
      if (!sourceIp) {
        return;
      }

      this.attackSessionsLoading = true;
      try {
        const data = await this.request(`/api/sessions/ip/${encodeURIComponent(sourceIp)}`, {
          query: { page: 1, page_size: 8 },
        });
        this.attackSessions = data.items || [];
        const preferredSession = this.attackSessions.find((item) => item.session_id === preferredSessionId);
        const nextSessionId = preferredSession?.session_id || this.attackSessions[0]?.session_id || "";
        this.activeAttackSessionId = nextSessionId;
        if (nextSessionId) {
          await this.loadAttackSessionData(nextSessionId);
        }
      } catch (error) {
        this.attackSessionErrorText = this.extractErrorMessage(error, "加载关联会话失败");
      } finally {
        this.attackSessionsLoading = false;
      }
    },
    async selectAttackSession(sessionId) {
      if (!sessionId || sessionId === this.activeAttackSessionId) {
        return;
      }
      await this.loadAttackSessionData(sessionId);
    },
    async loadAttackSessionData(sessionId) {
      if (!sessionId) {
        return;
      }

      this.attackSessionDataLoading = true;
      this.attackSessionDataErrorText = "";
      this.activeAttackSessionId = sessionId;

      try {
        const [timeline, evidence] = await Promise.all([
          this.request(`/api/replay/${encodeURIComponent(sessionId)}/timeline`),
          this.request(`/api/evidence/${encodeURIComponent(sessionId)}`),
        ]);
        this.attackSessionTimeline = timeline;
        this.attackSessionEvidence = evidence;
      } catch (error) {
        this.attackSessionTimeline = null;
        this.attackSessionEvidence = null;
        this.attackSessionDataErrorText = this.extractErrorMessage(error, "加载会话详情失败");
      } finally {
        this.attackSessionDataLoading = false;
      }
    },
    async exportActiveAttackSessionEvidence(format) {
      if (!this.activeAttackSessionId) {
        return;
      }
      const data = await this.request(`/api/evidence/${encodeURIComponent(this.activeAttackSessionId)}/export`, {
        method: "POST",
        query: { format },
      });
      if (data.file?.id) {
        await this.downloadFile(data.file.id);
      }
      this.attackSessionEvidence = await this.request(`/api/evidence/${encodeURIComponent(this.activeAttackSessionId)}`);
    },
    async openReplayTabForSession(sessionId, sourceIp) {
      if (!sessionId) {
        return;
      }
      this.closeAttackDetail();
      this.closeReplayDetail();
      this.resetReplayFilters();
      this.replaySourceIp = sourceIp || "";
      this.replaySessionId = sessionId;
      this.replayByIp = null;
      this.replayTimeline = null;
      await this.switchTab("replay");
    },
    resetReplayWorkbench() {
      this.replaySourceIp = "";
      this.replaySessionId = "";
      this.replayByIp = null;
      this.replayErrorText = "";
      this.replayTimeline = null;
      this.replayTimelineErrorText = "";
      this.selectedReplayEventId = "";
      this.replayEvidenceDrawerOpen = false;
      this.replayDetailModalOpen = false;
      this.evidenceData = null;
      this.evidenceVerifyLoadingMap = {};
      this.evidenceVerifyResults = {};
      this.resetReplayFilters();
    },
    submitReplayCommand() {
      if (this.replaySourceIp) {
        this.loadReplayByIp();
        return;
      }
      if (this.replaySessionId) {
        this.loadReplayTimeline();
      }
    },
    async selectReplaySession(sessionId) {
      if (!sessionId) {
        return;
      }
      this.closeReplayDetail();
      this.replaySessionId = sessionId;
      await this.loadReplayTimeline();
    },
    openReplayEventDetail(eventId) {
      if (!eventId) {
        return;
      }
      this.selectedReplayEventId = eventId;
      this.replayDetailModalOpen = true;
    },
    closeReplayDetail() {
      this.replayDetailModalOpen = false;
    },
    toggleReplayEvidenceDrawer() {
      if (!this.replaySessionId && !(this.evidenceData?.files || []).length) {
        return;
      }
      this.replayEvidenceDrawerOpen = !this.replayEvidenceDrawerOpen;
    },
    async loadReplayByIp({ preferredSessionId = this.replaySessionId, loadTimeline = true } = {}) {
      if (!this.replaySourceIp) {
        this.replayByIp = null;
        this.replayErrorText = "";
        return;
      }
      this.closeReplayDetail();
      this.replaySourceLoading = true;
      this.replayErrorText = "";
      try {
        this.replayByIp = await this.request(`/api/replay/${encodeURIComponent(this.replaySourceIp)}`);
        const matchedSession = this.replaySessions.find((item) => item.session_id === preferredSessionId);
        const nextSessionId = matchedSession?.session_id || this.replaySessions[0]?.session_id || "";
        if (nextSessionId) {
          this.replaySessionId = nextSessionId;
          if (loadTimeline) {
            await this.loadReplayTimeline({ syncSourceContext: false });
          }
        } else if (loadTimeline) {
          this.replaySessionId = "";
          this.replayTimeline = null;
          this.evidenceData = null;
          this.selectedReplayEventId = "";
        }
      } catch (error) {
        this.replayByIp = null;
        this.replayErrorText = this.extractErrorMessage(error, "加载来源回放失败");
      } finally {
        this.replaySourceLoading = false;
      }
    },
    async loadReplayTimeline({ syncSourceContext = true } = {}) {
      if (!this.replaySessionId) {
        this.replayTimeline = null;
        this.evidenceData = null;
        this.replayTimelineErrorText = "";
        this.selectedReplayEventId = "";
        this.closeReplayDetail();
        return;
      }
      this.closeReplayDetail();
      this.replayTimelineLoading = true;
      this.replayTimelineErrorText = "";
      try {
        const [timeline, evidence] = await Promise.all([
          this.request(`/api/replay/${encodeURIComponent(this.replaySessionId)}/timeline`),
          this.request(`/api/evidence/${encodeURIComponent(this.replaySessionId)}`),
        ]);
        this.replayTimeline = timeline;
        this.evidenceData = evidence;
        const currentEvent = (timeline.timeline || []).find((item) => item.event_id === this.selectedReplayEventId);
        this.selectedReplayEventId = currentEvent?.event_id || timeline.timeline?.[0]?.event_id || "";
        const sourceIp = timeline.session?.source_ip || "";
        if (sourceIp && this.replaySourceIp !== sourceIp) {
          this.replaySourceIp = sourceIp;
        }
        if (
          syncSourceContext &&
          sourceIp &&
          (!this.replayByIp || this.replayByIp.source_ip !== sourceIp)
        ) {
          await this.loadReplayByIp({
            preferredSessionId: timeline.session?.session_id || this.replaySessionId,
            loadTimeline: false,
          });
        }
      } catch (error) {
        this.replayTimeline = null;
        this.evidenceData = null;
        this.selectedReplayEventId = "";
        this.closeReplayDetail();
        this.replayTimelineErrorText = this.extractErrorMessage(error, "加载会话回放失败");
      } finally {
        this.replayTimelineLoading = false;
      }
    },
    async exportEvidence(format) {
      if (!this.replaySessionId) {
        return;
      }
      try {
        const data = await this.request(`/api/evidence/${encodeURIComponent(this.replaySessionId)}/export`, {
          method: "POST",
          query: { format },
        });
        if (data.file?.id) {
          await this.downloadFile(data.file.id);
        }
        this.evidenceData = await this.request(`/api/evidence/${encodeURIComponent(this.replaySessionId)}`);
      } catch (error) {
        this.replayTimelineErrorText = this.extractErrorMessage(error, "导出会话证据失败");
      }
    },
    resetReplayFilters() {
      this.replayFilters = {
        event_type: "",
        risk_level: "",
        keyword: "",
      };
    },
    isEvidenceVerifying(fileId) {
      return Boolean(this.evidenceVerifyLoadingMap[fileId]);
    },
    isEvidenceVerifyFailed(fileId) {
      const result = this.evidenceVerifyResults[fileId];
      return Boolean(result && result.verified === false);
    },
    evidenceVerifyText(fileId) {
      const result = this.evidenceVerifyResults[fileId];
      if (!result) {
        return "";
      }
      if (result.error) {
        return result.error;
      }
      if (result.verified) {
        return `完整性校验通过 · ${this.dateText(result.checked_at)}`;
      }
      return "完整性校验失败";
    },
    async verifyEvidenceFile(fileId) {
      if (!fileId || this.isEvidenceVerifying(fileId)) {
        return;
      }

      this.evidenceVerifyLoadingMap = {
        ...this.evidenceVerifyLoadingMap,
        [fileId]: true,
      };

      try {
        const data = await this.request(`/api/files/${fileId}/verify`);
        this.evidenceVerifyResults = {
          ...this.evidenceVerifyResults,
          [fileId]: data,
        };
      } catch (error) {
        this.evidenceVerifyResults = {
          ...this.evidenceVerifyResults,
          [fileId]: {
            verified: false,
            error: this.extractErrorMessage(error, "校验证据失败"),
          },
        };
      } finally {
        const nextLoading = { ...this.evidenceVerifyLoadingMap };
        delete nextLoading[fileId];
        this.evidenceVerifyLoadingMap = nextLoading;
      }
    },
    async downloadFile(fileId) {
      const result = await requestBlob({
        apiBase: this.apiBase,
        token: this.token,
        path: `/api/files/${fileId}/download`,
      });
      const url = window.URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = this.resolveFilename(result.contentDisposition, `evidence-${fileId}`);
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    },
    resolveFilename(contentDisposition, fallback) {
      const match = /filename=\"?([^\";]+)\"?/i.exec(contentDisposition || "");
      return match?.[1] || fallback;
    },
    extractErrorMessage(error, fallback) {
      return error?.message || fallback;
    },
    runtimeStatusLabel(value) {
      const normalized = String(value || "").toLowerCase();
      return {
        running: "运行中",
        stopped: "已停止",
        exited: "已退出",
        missing: "容器缺失",
      }[normalized] || (value || "-");
    },
    heartbeatStatusLabel(value) {
      const normalized = String(value || "").toLowerCase();
      return {
        online: "在线",
        stale: "滞后",
        offline: "离线",
        unknown: "未知",
      }[normalized] || (value || "-");
    },
    honeypotRuntimeTone(item) {
      const status = String(item?.runtime_status || "").toLowerCase();
      if (status === "running") {
        return "ok";
      }
      if (status === "missing" || status === "exited") {
        return "pending";
      }
      return "fail";
    },
    honeypotHeartbeatTone(item) {
      const state = String(item?.heartbeat_state || "").toLowerCase();
      if (state === "online") {
        return "ok";
      }
      if (state === "stale" || state === "unknown") {
        return "pending";
      }
      return "fail";
    },
    honeypotImageLabel(key) {
      const item = (this.honeypotCatalog.items || []).find((entry) => entry.key === key);
      return item?.label || key || "-";
    },
    honeypotEndpoint(item) {
      if (!item) {
        return "-";
      }
      const host = item.host_ip || item.bind_host || "0.0.0.0";
      const port = item.exposed_port || "-";
      return `${host}:${port}`;
    },
    honeypotNeedsAttention(item) {
      if (!item) {
        return false;
      }
      const runtimeStatus = String(item.runtime_status || "").toLowerCase();
      const heartbeatState = String(item.heartbeat_state || "").toLowerCase();
      return Boolean(
        item.last_error ||
        runtimeStatus === "missing" ||
        runtimeStatus === "exited" ||
        (runtimeStatus === "running" && ["stale", "offline", "unknown"].includes(heartbeatState)),
      );
    },
    honeypotAttentionText(item) {
      if (!item) {
        return "-";
      }
      if (item.last_error) {
        return this.shortHash(item.last_error, 24);
      }
      const runtimeStatus = String(item.runtime_status || "").toLowerCase();
      const heartbeatState = String(item.heartbeat_state || "").toLowerCase();
      if (runtimeStatus === "missing") {
        return "容器缺失";
      }
      if (runtimeStatus === "exited") {
        return "容器已退出";
      }
      if (runtimeStatus === "running" && heartbeatState === "stale") {
        return "心跳滞后";
      }
      if (runtimeStatus === "running" && heartbeatState === "offline") {
        return "运行中但已离线";
      }
      if (runtimeStatus === "running" && heartbeatState === "unknown") {
        return "缺少心跳";
      }
      return "正常";
    },
    canStartHoneypot(item) {
      if (!item || this.honeypotBusy) {
        return false;
      }
      return String(item.runtime_status || "").toLowerCase() !== "running";
    },
    canStopHoneypot(item) {
      if (!item || this.honeypotBusy) {
        return false;
      }
      return String(item.runtime_status || "").toLowerCase() === "running";
    },
    async toggleHoneypotCreatePanel() {
      const nextOpen = !this.honeypotCreatePanelOpen;
      if (nextOpen && !(this.honeypotCatalog.items || []).length) {
        try {
          await this.loadHoneypotCatalog();
        } catch (error) {
          return;
        }
      }
      this.honeypotCreatePanelOpen = nextOpen;
    },
    selectHoneypot(instanceId) {
      this.selectedHoneypotId = instanceId;
    },
    clearHoneypotFilter(key) {
      if (key === "only_attention") {
        this.honeypotQuery.only_attention = false;
        return;
      }
      if (Object.prototype.hasOwnProperty.call(this.honeypotQuery, key)) {
        this.honeypotQuery[key] = "";
      }
    },
    resetHoneypotFilters() {
      this.honeypotQuery = createDefaultHoneypotQuery();
    },
    applyHoneypotCatalogPreset() {
      if (!this.selectedHoneypotCatalog) {
        return;
      }
      this.honeypotForm.exposed_port =
        this.selectedHoneypotCatalog.default_exposed_port || this.honeypotForm.exposed_port;
    },
    async loadHoneypotCatalog() {
      this.honeypotErrorText = "";
      try {
        const data = await this.request("/api/honeypots/catalog");
        this.honeypotCatalog = data || { items: [] };
        if (!this.selectedHoneypotCatalog && this.honeypotCatalog.items?.length) {
          this.honeypotForm.image_key = this.honeypotCatalog.items[0].key;
          this.honeypotForm.exposed_port =
            this.honeypotCatalog.items[0].default_exposed_port || this.honeypotForm.exposed_port;
        }
      } catch (error) {
        this.honeypotErrorText = this.extractErrorMessage(error, "加载镜像目录失败");
        throw error;
      }
    },
    async loadHoneypots() {
      this.honeypotListLoading = true;
      this.honeypotErrorText = "";
      try {
        const data = await this.request("/api/honeypots", {
          query: {
            page: 1,
            page_size: 50,
          },
        });
        this.honeypots = data || { items: [], total: 0, summary: {} };
        const currentId = this.selectedHoneypotId;
        const hasCurrent = (this.honeypots.items || []).some((item) => item.id === currentId);
        this.selectedHoneypotId = hasCurrent ? currentId : this.honeypots.items?.[0]?.id || null;
      } catch (error) {
        this.honeypotErrorText = this.extractErrorMessage(error, "加载蜜罐实例失败");
        throw error;
      } finally {
        this.honeypotListLoading = false;
      }
    },
    async ensureAttackHoneypotOptions() {
      if ((this.honeypots.items || []).length) {
        return;
      }
      try {
        const data = await this.request("/api/honeypots", {
          query: {
            page: 1,
            page_size: 100,
          },
        });
        this.honeypots = data || { items: [], total: 0, summary: {} };
      } catch (error) {
        // 攻击页只把蜜罐实例作为筛选枚举源，失败时不阻断主列表。
      }
    },
    async createHoneypot() {
      if (!this.honeypotForm.name || !this.honeypotForm.image_key) {
        this.honeypotErrorText = "请填写蜜罐名称并选择镜像枚举";
        return;
      }
      this.honeypotBusy = true;
      this.honeypotStartMessage = "正在创建并启动蜜罐实例...";
      this.honeypotStartModalOpen = true;
      this.honeypotErrorText = "";
      this.honeypotActionText = "";
      try {
        const created = await this.request("/api/honeypots", {
          method: "POST",
          body: {
            name: this.honeypotForm.name,
            honeypot_type: "web",
            image_key: this.honeypotForm.image_key,
            exposed_port: this.honeypotForm.exposed_port,
          },
        });
        this.honeypotStartMessage = "创建成功，正在刷新实例状态...";
        this.honeypotActionText = `实例 ${created?.name || this.honeypotForm.name} 已创建并启动`;
        this.honeypotForm.name = "";
        this.honeypotForm.exposed_port = this.selectedHoneypotCatalog?.default_exposed_port || 18080;
        await this.loadHoneypots();
        this.selectedHoneypotId = created?.id || this.selectedHoneypotId;
        this.honeypotCreatePanelOpen = false;
      } catch (error) {
        this.honeypotErrorText = this.extractErrorMessage(error, "创建或启动蜜罐失败");
      } finally {
        this.honeypotStartModalOpen = false;
        this.honeypotBusy = false;
      }
    },
    async startHoneypot(instanceId) {
      this.honeypotBusy = true;
      this.honeypotStartMessage = "正在启动蜜罐实例...";
      this.honeypotStartModalOpen = true;
      this.honeypotErrorText = "";
      this.honeypotActionText = "";
      try {
        const data = await this.request(`/api/honeypots/${instanceId}/start`, { method: "POST", body: {} });
        this.honeypotStartMessage = "启动成功，正在刷新实例状态...";
        this.honeypotActionText = `实例 ${data?.name || `#${instanceId}`} 已启动`;
        await this.loadHoneypots();
        this.selectedHoneypotId = instanceId;
      } catch (error) {
        this.honeypotErrorText = this.extractErrorMessage(error, "启动蜜罐失败");
      } finally {
        this.honeypotStartModalOpen = false;
        this.honeypotBusy = false;
      }
    },
    async stopHoneypot(instanceId) {
      this.honeypotBusy = true;
      this.honeypotErrorText = "";
      this.honeypotActionText = "";
      try {
        const data = await this.request(`/api/honeypots/${instanceId}/stop`, { method: "POST", body: {} });
        this.honeypotActionText = `实例 ${data?.name || `#${instanceId}`} 已停止`;
        await this.loadHoneypots();
        this.selectedHoneypotId = instanceId;
      } catch (error) {
        this.honeypotErrorText = this.extractErrorMessage(error, "停止蜜罐失败");
      } finally {
        this.honeypotBusy = false;
      }
    },
    async deleteHoneypot(instanceId) {
      if (!window.confirm(`确认删除蜜罐 #${instanceId} ?`)) {
        return;
      }
      this.honeypotBusy = true;
      this.honeypotErrorText = "";
      this.honeypotActionText = "";
      try {
        await this.request(`/api/honeypots/${instanceId}`, { method: "DELETE" });
        this.honeypotActionText = `实例 #${instanceId} 已删除`;
        if (this.selectedHoneypotId === instanceId) {
          this.selectedHoneypotId = null;
        }
        await this.loadHoneypots();
      } catch (error) {
        this.honeypotErrorText = this.extractErrorMessage(error, "删除蜜罐失败");
      } finally {
        this.honeypotBusy = false;
      }
    },
  },
};
</script>

<style scoped>
.console-page {
  min-height: calc(100vh - 64px);
  padding: 24px;
  background:
    linear-gradient(rgba(115, 187, 255, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(115, 187, 255, 0.04) 1px, transparent 1px),
    radial-gradient(circle at 18% 14%, rgba(41, 208, 255, 0.08), transparent 24%),
    radial-gradient(circle at 84% 16%, rgba(45, 123, 255, 0.08), transparent 22%),
    radial-gradient(circle at 50% 100%, rgba(9, 119, 176, 0.12), transparent 28%),
    #0b1628;
  background-size:
    32px 32px,
    32px 32px,
    auto,
    auto,
    auto;
  color: #dff9ff;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
}

.console-shell {
  width: min(1680px, 100%);
  margin: 0 auto;
  display: grid;
  gap: 18px;
}

.card {
  position: relative;
  border: 1px solid rgba(100, 201, 255, 0.18);
  border-radius: 18px;
  background:
    linear-gradient(180deg, rgba(16, 40, 74, 0.18), transparent 20%),
    linear-gradient(180deg, rgba(9, 27, 52, 0.94), rgba(8, 20, 42, 0.88));
  box-shadow:
    inset 0 0 20px rgba(44, 149, 255, 0.08),
    0 12px 32px rgba(0, 0, 0, 0.18);
}

.card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  border: 1px solid rgba(123, 215, 255, 0.05);
  pointer-events: none;
}

.status-pill {
  display: inline-block;
  padding: 4px 9px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.18);
  background: rgba(14, 54, 95, 0.45);
  color: #dff9ff;
}

.status-pill.ok {
  color: #6dffcb;
}

.status-pill.pending {
  color: #ffd36f;
}

.status-pill.fail {
  color: #ff957d;
}

.actions,
.tab-row,
.inline-form {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.tab-row {
  padding: 8px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(7, 20, 40, 0.72);
  width: fit-content;
}

.btn,
.tab-btn {
  appearance: none;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 999px;
  padding: 10px 16px;
  cursor: pointer;
  background: linear-gradient(135deg, rgba(17, 83, 153, 0.8), rgba(14, 43, 100, 0.76));
  color: #dff9ff;
  text-decoration: none;
  font: inherit;
  box-shadow: inset 0 0 16px rgba(44, 149, 255, 0.18);
}

.btn.ghost {
  background: rgba(11, 28, 54, 0.72);
}

.btn.danger {
  border-color: rgba(255, 109, 92, 0.26);
  background: linear-gradient(135deg, rgba(145, 39, 40, 0.88), rgba(108, 27, 36, 0.82));
  color: #ffe4de;
  box-shadow: inset 0 0 16px rgba(255, 89, 71, 0.14);
}

.btn.ghost.danger {
  background: rgba(60, 17, 24, 0.64);
}

.btn.mini {
  padding: 8px 12px;
}

.tab-btn.active {
  border-color: rgba(100, 201, 255, 0.32);
  background: rgba(16, 80, 148, 0.32);
  color: #f1fdff;
}

.console-overview-grid {
  display: grid;
  grid-template-columns: minmax(320px, 0.92fr) minmax(420px, 1.08fr);
  gap: 18px;
}

.console-context-card,
.console-priority-card {
  display: grid;
  gap: 14px;
}

.context-chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.context-chip {
  display: grid;
  gap: 4px;
  min-width: 0;
  padding: 10px 12px;
  border-radius: 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(9, 31, 58, 0.64);
}

.context-chip em {
  color: rgba(171, 224, 255, 0.64);
  font-style: normal;
  font-size: 11px;
}

.context-chip strong {
  color: #f1fdff;
  font-size: 13px;
  word-break: break-word;
}

.priority-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: 10px;
}

.priority-item {
  appearance: none;
  width: 100%;
  border: 1px solid rgba(100, 201, 255, 0.12);
  border-radius: 18px;
  padding: 12px 14px;
  background: rgba(9, 31, 58, 0.64);
  color: inherit;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  text-align: left;
  cursor: pointer;
  transition:
    border-color 160ms ease,
    background 160ms ease,
    transform 160ms ease;
}

.priority-item:hover {
  border-color: rgba(100, 201, 255, 0.24);
  background: rgba(13, 42, 78, 0.72);
  transform: translateY(-1px);
}

.panel-grid,
.attack-stage,
.attack-layout,
.replay-layout,
.honeypot-layout {
  display: grid;
  gap: 18px;
  align-items: start;
}

.panel-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
}

.attack-shell {
  grid-template-columns: 300px minmax(0, 1.18fr) minmax(360px, 0.92fr);
}

.attack-stage-card {
  display: grid;
  gap: 16px;
}

.replay-shell {
  grid-template-columns: 300px minmax(0, 1.12fr) minmax(380px, 0.88fr);
}

.card {
  padding: 18px;
}

.kpi-card span {
  display: block;
  font-size: 13px;
  color: rgba(171, 224, 255, 0.72);
}

.kpi-card strong {
  display: block;
  margin-top: 8px;
  font-size: 30px;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  color: #f1fdff;
  text-shadow: 0 0 16px rgba(84, 214, 255, 0.2);
}

.wide {
  grid-column: span 2;
}

.section-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}

.section-head h2,
.detail-body h3,
.evidence-panel h3 {
  margin: 0;
  color: #ecfbff;
  letter-spacing: 0.05em;
}

.section-note {
  margin: 6px 0 0;
  color: rgba(171, 224, 255, 0.64);
  font-size: 12px;
}

.attack-card-head {
  align-items: flex-start;
}

.attack-toolbar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.result-pill {
  display: inline-flex;
  align-items: center;
  min-height: 36px;
  padding: 0 14px;
  border-radius: 999px;
  border: 1px solid rgba(100, 201, 255, 0.18);
  background: rgba(10, 36, 68, 0.76);
  color: rgba(223, 249, 255, 0.88);
  font-size: 12px;
}

.attack-filter-panel {
  padding: 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(7, 27, 52, 0.46);
}

.attack-filter-stack {
  display: grid;
  gap: 14px;
}

.attack-stage-toolbar {
  display: grid;
  gap: 14px;
}

.attack-toolbar-field {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 36px;
  padding: 0 12px;
  border-radius: 999px;
  border: 1px solid rgba(100, 201, 255, 0.16);
  background: rgba(10, 33, 62, 0.72);
}

.attack-toolbar-field span {
  color: rgba(171, 224, 255, 0.72);
  font-size: 12px;
  white-space: nowrap;
}

.attack-toolbar-field select {
  min-width: 58px;
  border: 0;
  padding: 0 18px 0 0;
  background-color: transparent;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6' fill='none'%3E%3Cpath d='M1 1L5 5L9 1' stroke='%238de8ff' stroke-width='1.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  background-position: right center;
  background-repeat: no-repeat;
  background-size: 10px 6px;
  color: #dff9ff;
  font: inherit;
  cursor: pointer;
  appearance: none;
  -webkit-appearance: none;
  -moz-appearance: none;
  color-scheme: dark;
}

.attack-toolbar-field select:focus {
  outline: none;
}

.attack-toolbar-field select option {
  background: #0b2444;
  color: #dff9ff;
}

.attack-stage-meta {
  display: grid;
  gap: 10px;
}

.attack-time-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
}

.attack-time-presets {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 0;
}

.attack-time-fields {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.attack-filter-form-shell {
  display: grid;
  gap: 12px;
}

.attack-primary-filter-row {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: 12px;
  align-items: end;
}

.attack-advanced-filter-row {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.attack-inline-field {
  gap: 5px;
}

.attack-inline-field span {
  color: rgba(171, 224, 255, 0.72);
  font-size: 12px;
}

.attack-time-field {
  min-width: 196px;
}

.attack-time-field input {
  min-width: 196px;
  padding: 9px 12px;
}

.attack-advanced-toggle {
  min-height: 44px;
  align-self: end;
}

.attack-advanced-toggle.active {
  border-color: rgba(100, 201, 255, 0.28);
  background: rgba(16, 80, 148, 0.24);
}

.time-range-btn,
.page-btn,
.detail-tab-btn {
  appearance: none;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 999px;
  padding: 8px 12px;
  background: rgba(10, 33, 62, 0.72);
  color: #dff9ff;
  font: inherit;
  cursor: pointer;
}

.time-range-btn.active,
.page-btn.active,
.detail-tab-btn.active {
  border-color: rgba(100, 201, 255, 0.32);
  background: rgba(16, 80, 148, 0.32);
  color: #f1fdff;
}

.time-range-btn:disabled,
.page-btn:disabled,
.detail-tab-btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.attack-filter-grid {
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin-bottom: 0;
}

.attack-filter-form {
  grid-template-columns: 1fr;
}

.attack-filter-ops {
  margin-bottom: 0;
}

.attack-filter-chip-row,
.attack-filter-selection {
  margin-bottom: 0;
}

.attack-ops-row {
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.inline-select {
  min-width: 132px;
  display: grid;
  gap: 6px;
}

.inline-select select {
  min-width: 132px;
}

.sort-toggle {
  min-width: 88px;
}

.inline-error {
  margin: 12px 0 0;
  color: #ffb6a0;
  font-size: 12px;
}

.inline-success {
  margin: 12px 0 0;
  color: #8ef2cf;
  font-size: 12px;
}

.filter-chip-row {
  margin-bottom: 14px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.filter-chip {
  appearance: none;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 999px;
  border: 1px solid rgba(100, 201, 255, 0.18);
  background: rgba(9, 31, 58, 0.72);
  color: #dff9ff;
  font: inherit;
  cursor: pointer;
}

.filter-chip strong {
  color: rgba(141, 232, 255, 0.92);
  font-size: 12px;
  line-height: 1;
}

.attack-bulk-bar {
  margin-bottom: 14px;
  padding: 12px 14px;
  border-radius: 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(8, 28, 55, 0.76);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.attack-filter-card,
.detail-card,
.replay-workbench-card,
.replay-inspector-card,
.honeypot-create-card,
.honeypot-detail-card {
  position: sticky;
  top: 86px;
  max-height: calc(100vh - 110px);
  overflow: auto;
}

.replay-workbench-card,
.replay-detail-card,
.replay-timeline-card,
.replay-inspector-card,
.honeypot-create-card,
.honeypot-list-card,
.honeypot-detail-card {
  display: grid;
  gap: 14px;
}

.honeypot-stage-card {
  display: grid;
  gap: 18px;
}

.honeypot-stage-head {
  margin-bottom: 0;
}

.honeypot-command-strip {
  display: grid;
  gap: 12px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.08);
}

.honeypot-toolbar {
  justify-content: flex-start;
}

.honeypot-toolbar .btn.active {
  border-color: rgba(100, 201, 255, 0.3);
  background: rgba(16, 80, 148, 0.28);
}

.honeypot-filter-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: end;
}

.honeypot-filter-row-compact {
  padding-top: 2px;
}

.honeypot-filter-field {
  flex: 1 1 240px;
  display: grid;
  gap: 6px;
}

.honeypot-create-panel {
  display: grid;
  gap: 12px;
  padding-top: 14px;
  border-top: 1px solid rgba(100, 201, 255, 0.08);
}

.honeypot-pane-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 12px;
}

.honeypot-pane-head h3 {
  margin: 0;
  color: #ecfbff;
  letter-spacing: 0.05em;
}

.honeypot-create-head {
  margin-bottom: 0;
}

.honeypot-create-form {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr)) auto;
  gap: 12px;
  align-items: end;
}

.honeypot-create-actions {
  align-self: end;
}

.honeypot-template-line {
  margin: 0;
  line-height: 1.6;
}

.honeypot-stage-body {
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  gap: 22px;
  min-height: 560px;
  align-items: start;
}

.honeypot-instance-rail {
  display: grid;
  gap: 14px;
  min-width: 0;
  padding-right: 18px;
  border-right: 1px solid rgba(100, 201, 255, 0.08);
}

.honeypot-rail-list {
  max-height: 560px;
  overflow: auto;
  padding-right: 4px;
  display: grid;
  gap: 4px;
}

.honeypot-rail-item {
  appearance: none;
  width: 100%;
  padding: 11px 0 11px 14px;
  border: 0;
  border-left: 2px solid transparent;
  border-radius: 0;
  background: transparent;
  color: #dff9ff;
  text-align: left;
  cursor: pointer;
  display: grid;
  gap: 6px;
  transition:
    border-color 160ms ease,
    background 160ms ease,
    color 160ms ease;
}

.honeypot-rail-item:hover {
  border-color: rgba(100, 201, 255, 0.2);
  background: rgba(10, 36, 68, 0.28);
}

.honeypot-rail-item.active {
  border-color: rgba(100, 201, 255, 0.34);
  background: rgba(16, 80, 148, 0.16);
}

.honeypot-rail-item.attention {
  background: rgba(88, 48, 28, 0.14);
}

.honeypot-rail-item.active.attention {
  background: rgba(125, 83, 44, 0.2);
}

.honeypot-rail-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.honeypot-rail-top strong {
  min-width: 0;
  color: #f1fdff;
  font-size: 13px;
  line-height: 1.4;
  overflow-wrap: anywhere;
}

.honeypot-rail-meta {
  display: grid;
  gap: 3px;
  color: rgba(189, 232, 255, 0.72);
  font-size: 12px;
}

.honeypot-detail-panel {
  display: grid;
  gap: 16px;
  min-width: 0;
}

.honeypot-detail-hero {
  margin: 0;
}

.honeypot-meta-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.honeypot-meta-grid-compact {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin-bottom: 12px;
}

.honeypot-meta-item {
  min-width: 0;
  padding: 8px 0;
  border-bottom: 1px solid rgba(100, 201, 255, 0.08);
  display: grid;
  gap: 6px;
}

.honeypot-meta-item span {
  color: rgba(171, 224, 255, 0.64);
  font-size: 12px;
}

.honeypot-meta-item strong {
  color: #f1fdff;
}

.honeypot-detail-sections {
  display: grid;
  grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
  gap: 14px;
}

.honeypot-detail-section {
  min-width: 0;
  display: grid;
  gap: 10px;
}

.honeypot-detail-section h3 {
  margin: 0;
  color: #ecfbff;
  letter-spacing: 0.05em;
}

.honeypot-runtime-details {
  border: 1px solid rgba(100, 201, 255, 0.12);
  border-radius: 16px;
  background: rgba(8, 29, 54, 0.36);
  overflow: hidden;
}

.honeypot-runtime-details summary {
  list-style: none;
  cursor: pointer;
  padding: 12px 14px;
  color: #dff9ff;
}

.honeypot-runtime-details summary::-webkit-details-marker {
  display: none;
}

.honeypot-runtime-details[open] summary {
  border-bottom: 1px solid rgba(100, 201, 255, 0.08);
}

.honeypot-runtime-details pre {
  margin: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.honeypot-stage-actions {
  justify-content: flex-start;
  padding-top: 2px;
}

.replay-stage-card {
  display: grid;
  gap: 18px;
}

.replay-stage-head {
  margin-bottom: 0;
}

.replay-stage-toolbar {
  display: grid;
  gap: 10px;
}

.replay-command-strip {
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.08);
}

.replay-command-row,
.replay-query-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: end;
}

.replay-query-field {
  flex: 1 1 220px;
  display: grid;
  gap: 6px;
}

.replay-query-field span {
  color: rgba(171, 224, 255, 0.72);
  font-size: 12px;
}

.replay-context-line {
  margin: 0;
  line-height: 1.6;
}

.replay-stage-body {
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  gap: 22px;
  align-items: start;
  min-height: 560px;
}

.replay-session-rail,
.replay-main-panel,
.replay-event-panel {
  display: grid;
  gap: 14px;
  min-width: 0;
}

.replay-session-rail {
  align-content: start;
  padding-right: 18px;
  border-right: 1px solid rgba(100, 201, 255, 0.08);
}

.replay-pane-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 12px;
}

.replay-pane-head h3 {
  margin: 0;
  color: #ecfbff;
  letter-spacing: 0.05em;
}

.session-rail-list {
  max-height: 520px;
  overflow: auto;
  padding-right: 4px;
  display: grid;
  gap: 4px;
}

.session-rail-item {
  appearance: none;
  width: 100%;
  padding: 10px 0 10px 14px;
  border: 0;
  border-left: 2px solid transparent;
  border-radius: 0;
  background: transparent;
  color: #dff9ff;
  text-align: left;
  cursor: pointer;
  display: grid;
  gap: 6px;
  transition:
    border-color 160ms ease,
    background 160ms ease,
    color 160ms ease;
}

.session-rail-item:hover {
  border-color: rgba(100, 201, 255, 0.22);
  background: rgba(10, 36, 68, 0.32);
}

.session-rail-item.active {
  border-color: rgba(100, 201, 255, 0.34);
  background: rgba(16, 80, 148, 0.18);
}

.session-rail-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.session-rail-top strong {
  min-width: 0;
  color: #f1fdff;
  font-size: 13px;
  line-height: 1.4;
  overflow-wrap: anywhere;
}

.session-rail-meta {
  display: grid;
  gap: 3px;
  font-size: 12px;
  color: rgba(189, 232, 255, 0.72);
}

.replay-filter-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: end;
  padding-bottom: 6px;
}

.replay-filter-field {
  flex: 1 1 240px;
  display: grid;
  gap: 6px;
}

.replay-event-table-scroll {
  border: 1px solid rgba(100, 201, 255, 0.1);
  border-radius: 16px;
  background: rgba(7, 27, 52, 0.34);
}

.replay-event-table {
  min-width: 960px;
  table-layout: fixed;
}

.replay-event-table td {
  text-align: center;
  vertical-align: middle;
  white-space: nowrap;
}

.replay-event-table .replay-time-col {
  width: 228px;
  min-width: 228px;
}

.replay-event-table .replay-risk-col {
  width: 226px;
  min-width: 226px;
}

.replay-event-table .replay-target-col {
  width: 270px;
  min-width: 270px;
}

.replay-event-table .replay-summary-col {
  width: 282px;
  min-width: 282px;
}

.replay-event-row {
  transition: background 160ms ease;
}

.replay-event-row:hover {
  background: rgba(15, 62, 114, 0.12);
}

.replay-event-row.selected {
  background: rgba(16, 80, 148, 0.22);
}

.replay-event-table .target-line {
  justify-content: center;
}

.replay-risk-line {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  flex-wrap: nowrap;
  white-space: nowrap;
}

.replay-risk-line .risk-badge {
  flex-shrink: 0;
}

.replay-type-inline {
  display: inline-block;
  white-space: nowrap;
}

.replay-drawer-shell {
  display: grid;
  gap: 0;
  padding-top: 4px;
  border-top: 1px solid rgba(100, 201, 255, 0.08);
}

.replay-drawer-toggle {
  appearance: none;
  justify-self: center;
  min-width: 188px;
  border: 1px solid rgba(100, 201, 255, 0.18);
  border-bottom: 0;
  border-radius: 16px 16px 0 0;
  padding: 10px 18px 8px;
  background: rgba(8, 31, 58, 0.64);
  color: #dff9ff;
  font: inherit;
  cursor: pointer;
  transform: translateY(1px);
  transition:
    border-color 160ms ease,
    background 160ms ease,
    color 160ms ease;
}

.replay-drawer-toggle:hover:not(:disabled),
.replay-drawer-toggle.active {
  border-color: rgba(100, 201, 255, 0.3);
  background: rgba(16, 80, 148, 0.32);
  color: #f1fdff;
}

.replay-drawer-toggle:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.replay-evidence-drawer {
  padding-top: 16px;
  border-top: 1px solid rgba(100, 201, 255, 0.08);
  display: grid;
  gap: 12px;
}

.replay-drawer-head {
  margin-bottom: 0;
}

.replay-rule-list {
  margin-top: 0;
}

.replay-detail-body {
  gap: 12px;
}

.replay-detail-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  color: rgba(201, 239, 255, 0.78);
  font-size: 13px;
  line-height: 1.6;
}

.replay-detail-meta .mono-text {
  overflow-wrap: anywhere;
}

.replay-detail-actions {
  justify-content: flex-start;
}

.replay-detail-pane-grid {
  margin-top: 2px;
}

.table {
  width: 100%;
  border-collapse: collapse;
}

.table th,
.table td {
  padding: 11px 10px;
  border-bottom: 1px solid rgba(100, 201, 255, 0.1);
  text-align: left;
  vertical-align: top;
  font-size: 13px;
  color: #dff9ff;
}

.table th {
  color: rgba(171, 224, 255, 0.72);
  text-align: center;
}

.table-sort-btn {
  appearance: none;
  width: 100%;
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  display: inline-flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  cursor: pointer;
  text-align: left;
}

.table-sort-btn strong {
  color: rgba(141, 232, 255, 0.92);
  font-size: 12px;
  line-height: 1;
}

.table-sort-btn:hover {
  color: #dff9ff;
}

.attack-table .select-col {
  width: 40px;
  min-width: 40px;
  padding-left: 6px;
  padding-right: 6px;
  text-align: center;
}

.row-link {
  cursor: pointer;
}

.row-link:hover {
  background: rgba(15, 62, 114, 0.18);
}

.row-link.selected {
  background: rgba(16, 80, 148, 0.26);
}

.table-scroll {
  overflow-x: auto;
  border-radius: 14px;
}

.attack-table-scroll {
  border: 1px solid rgba(100, 201, 255, 0.1);
  background: rgba(7, 27, 52, 0.34);
}

.attack-grid-table {
  min-width: 1180px;
  table-layout: fixed;
}

.attack-grid-table td {
  text-align: center;
  vertical-align: middle;
  white-space: nowrap;
}

.attack-grid-table .time-col {
  min-width: 220px;
  width: 220px;
}

.attack-grid-table .source-col {
  min-width: 200px;
  width: 200px;
}

.attack-grid-table .target-col {
  min-width: 300px;
  width: 300px;
}

.attack-grid-table .type-col {
  min-width: 126px;
  width: 126px;
}

.attack-grid-table .risk-col {
  min-width: 120px;
  width: 120px;
}

.attack-grid-table .session-col {
  min-width: 260px;
  width: 260px;
}

.attack-grid-table .action-col {
  width: 150px;
  min-width: 150px;
  text-align: center;
}

.attack-grid-table th.action-col,
.attack-grid-table td.action-col {
  text-align: center;
}

.attack-grid-table td.action-col {
  vertical-align: middle;
}

.attack-table-row {
  transition: background 160ms ease;
}

.attack-table-row:hover {
  background: rgba(15, 62, 114, 0.12);
}

.attack-table-row.selected {
  background: rgba(16, 80, 148, 0.22);
}

.attack-list-foot {
  margin-top: 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.pagination {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.select-checkbox {
  width: 14px;
  height: 14px;
  margin: 0;
  border: 1px solid rgba(100, 201, 255, 0.32);
  border-radius: 4px;
  background: linear-gradient(180deg, rgba(9, 31, 58, 0.92), rgba(7, 23, 44, 0.92));
  box-shadow:
    inset 0 0 0 1px rgba(123, 215, 255, 0.05),
    0 0 0 0 rgba(46, 201, 255, 0);
  cursor: pointer;
  appearance: none;
  -webkit-appearance: none;
  transition:
    border-color 160ms ease,
    background 160ms ease,
    box-shadow 160ms ease;
}

.select-checkbox:hover {
  border-color: rgba(123, 215, 255, 0.48);
  box-shadow:
    inset 0 0 0 1px rgba(123, 215, 255, 0.08),
    0 0 0 2px rgba(46, 201, 255, 0.08);
}

.select-checkbox:checked,
.select-checkbox.indeterminate {
  border-color: rgba(107, 216, 255, 0.72);
  background-color: rgba(17, 92, 168, 0.92);
  background-position: center;
  background-repeat: no-repeat;
  box-shadow:
    inset 0 0 0 1px rgba(198, 244, 255, 0.14),
    0 0 0 3px rgba(46, 201, 255, 0.12);
}

.select-checkbox:checked {
  background-image:
    linear-gradient(180deg, rgba(55, 170, 244, 0.96), rgba(24, 104, 196, 0.96)),
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none'%3E%3Cpath d='M3.5 8.3 6.5 11.1 12.5 4.9' stroke='white' stroke-width='2.1' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  background-size: auto, 10px 10px;
}

.select-checkbox.indeterminate {
  background-image:
    linear-gradient(180deg, rgba(55, 170, 244, 0.96), rgba(24, 104, 196, 0.96)),
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none'%3E%3Cpath d='M4 8H12' stroke='white' stroke-width='2.1' stroke-linecap='round'/%3E%3C/svg%3E");
  background-size: auto, 10px 10px;
}

.select-checkbox:disabled {
  cursor: not-allowed;
  opacity: 0.45;
  box-shadow: none;
}

.attack-row-actions {
  display: flex;
  justify-content: center;
  gap: 8px;
  width: 100%;
}

.cell-stack {
  display: grid;
  gap: 4px;
}

.attack-grid-table .cell-stack {
  justify-items: center;
  text-align: center;
}

.inline-text {
  display: block;
  width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono-text {
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  letter-spacing: 0.03em;
}

.target-line {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.attack-grid-table .target-line {
  justify-content: center;
}

.target-line-compact {
  flex-wrap: nowrap;
  width: 100%;
}

.attack-grid-table .target-line-compact .path-text {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.method-pill,
.type-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.14);
  background: rgba(9, 41, 78, 0.76);
  color: #8de8ff;
  font-size: 11px;
  letter-spacing: 0.04em;
  white-space: nowrap;
}

.path-text {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.attack-preview-text {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  text-align: center;
}

.type-text {
  display: inline-block;
  white-space: nowrap;
}

.rule-text {
  display: inline-block;
  white-space: normal;
  word-break: break-word;
  line-height: 1.5;
  text-align: center;
}

.risk-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid rgba(123, 215, 255, 0.16);
  background: rgba(10, 36, 68, 0.76);
  white-space: nowrap;
}

.risk-badge.low {
  color: #8de8ff;
}

.risk-badge.medium {
  color: #ffd36f;
}

.risk-badge.high {
  color: #ffb35c;
}

.risk-badge.critical {
  color: #ff8e7a;
}

.stack-list,
.event-feed {
  list-style: none;
  padding: 0;
  margin: 0;
}

.stack-list li,
.event-feed li {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 0;
  border-bottom: 1px solid rgba(100, 201, 255, 0.1);
}

.event-feed li {
  display: grid;
  grid-template-columns: 168px 150px 130px 1fr;
  align-items: start;
}

.event-feed.compact li {
  grid-template-columns: 168px 120px 1fr;
}

.event-feed em,
.event-feed i {
  font-style: normal;
  color: rgba(189, 232, 255, 0.72);
}

.detail-card pre,
.detail-body pre,
.honeypot-detail-card pre,
.payload-modal-pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 14px;
  border-radius: 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(12, 33, 63, 0.72);
  color: #dff9ff;
  font-size: 12px;
  line-height: 1.55;
}

.detail-workbench {
  display: grid;
  gap: 16px;
}

.detail-hero {
  padding: 16px 18px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(7, 27, 52, 0.48);
}

.detail-kicker {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}

.detail-title {
  margin-top: 12px;
  font-size: 22px;
  line-height: 1.25;
}

.detail-preview {
  margin: 10px 0 0;
  color: rgba(201, 239, 255, 0.78);
  line-height: 1.6;
}

.detail-summary-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.attack-detail-summary-grid {
  grid-template-columns: minmax(152px, 0.9fr) minmax(112px, 0.62fr) minmax(288px, 1.48fr);
  grid-template-areas:
    "source region session"
    "honeypot rules time";
}

.attack-detail-summary-grid .detail-summary-card {
  min-width: 0;
}

.attack-detail-summary-grid .detail-summary-card.is-source {
  grid-area: source;
}

.attack-detail-summary-grid .detail-summary-card.is-region {
  grid-area: region;
}

.attack-detail-summary-grid .detail-summary-card.is-session {
  grid-area: session;
}

.attack-detail-summary-grid .detail-summary-card.is-honeypot {
  grid-area: honeypot;
}

.attack-detail-summary-grid .detail-summary-card.is-rules {
  grid-area: rules;
}

.attack-detail-summary-grid .detail-summary-card.is-time {
  grid-area: time;
}

.detail-summary-card {
  min-width: 0;
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(9, 31, 58, 0.64);
  display: grid;
  gap: 6px;
}

.detail-summary-card span {
  color: rgba(171, 224, 255, 0.64);
  font-size: 12px;
}

.detail-summary-card strong {
  color: #f1fdff;
}

.session-id-text {
  display: block;
  min-width: 0;
  font-family: "Rajdhani", "Noto Sans SC", sans-serif;
  letter-spacing: 0.03em;
  line-height: 1.45;
  overflow-wrap: anywhere;
  word-break: break-all;
}

.detail-tab-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.detail-pane {
  display: grid;
  gap: 14px;
}

.detail-pane-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.rule-list {
  display: grid;
  gap: 12px;
}

.rule-card {
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(9, 31, 58, 0.64);
}

.rule-card strong {
  display: block;
  color: #ecfbff;
}

.rule-card p {
  margin: 8px 0 0;
  color: rgba(189, 232, 255, 0.74);
  line-height: 1.55;
  font-size: 13px;
}

.detail-empty {
  padding: 16px 0;
}

.session-workbench {
  display: grid;
  gap: 14px;
  padding-top: 6px;
  border-top: 1px solid rgba(100, 201, 255, 0.08);
}

.session-card-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}

.session-card {
  appearance: none;
  width: 100%;
  padding: 14px 16px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  border-radius: 18px;
  background: rgba(9, 31, 58, 0.64);
  color: #dff9ff;
  text-align: left;
  cursor: pointer;
  display: grid;
  gap: 10px;
  transition:
    border-color 160ms ease,
    transform 160ms ease,
    box-shadow 160ms ease,
    background 160ms ease;
}

.session-card:hover {
  border-color: rgba(100, 201, 255, 0.24);
  transform: translateY(-1px);
}

.session-card.active {
  border-color: rgba(100, 201, 255, 0.34);
  background: linear-gradient(180deg, rgba(13, 55, 99, 0.84), rgba(9, 31, 58, 0.72));
  box-shadow: inset 0 0 18px rgba(44, 149, 255, 0.14);
}

.session-card-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 10px;
}

.session-card-top strong {
  min-width: 0;
  font-size: 14px;
  color: #f1fdff;
  overflow-wrap: anywhere;
}

.session-card-meta {
  display: grid;
  gap: 4px;
  font-size: 12px;
  color: rgba(189, 232, 255, 0.72);
}

.session-card-summary {
  margin: 0;
  color: rgba(201, 239, 255, 0.82);
  font-size: 12px;
  line-height: 1.6;
  display: -webkit-box;
  overflow: hidden;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
}

.session-detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.08fr) minmax(0, 0.92fr);
  gap: 14px;
}

.session-panel {
  min-width: 0;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(9, 31, 58, 0.64);
}

.payload-preview-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.payload-preview-card {
  min-width: 0;
  padding: 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(9, 31, 58, 0.64);
  display: grid;
  gap: 12px;
}

.payload-preview-head {
  margin-bottom: 0;
}

.payload-preview {
  margin: 0;
  max-height: 240px;
  overflow: auto;
  overscroll-behavior: contain;
  scrollbar-gutter: stable;
}

.evidence-stats-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin-bottom: 14px;
}

.evidence-file-list li {
  align-items: center;
}

.verify-chip {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  padding: 4px 10px;
  border-radius: 999px;
  background: rgba(13, 55, 99, 0.46);
  color: rgba(141, 232, 255, 0.88);
  font-size: 11px;
}

.verify-chip.failed {
  background: rgba(108, 27, 36, 0.42);
  color: #ffccb9;
}

.timeline-feed li {
  grid-template-columns: 152px 100px 1fr;
}

.timeline-feed strong {
  color: #f1fdff;
}

.detail-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 18px;
  margin-bottom: 16px;
  font-size: 13px;
  color: rgba(201, 239, 255, 0.76);
}

.detail-grid,
.filter-grid {
  display: grid;
  gap: 14px;
}

.detail-grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin-bottom: 14px;
}

.filter-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin-bottom: 14px;
}

.honeypot-form {
  margin-bottom: 0;
}

.catalog-card {
  margin-top: 14px;
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 201, 255, 0.12);
  background: rgba(10, 31, 59, 0.62);
  display: grid;
  gap: 6px;
}

.catalog-label {
  font-size: 16px;
  color: #f1fdff;
}

.catalog-meta,
.muted-text {
  color: rgba(189, 232, 255, 0.72);
  font-size: 12px;
}

.status-stack {
  display: grid;
  gap: 4px;
}

.action-cluster {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

label {
  display: grid;
  gap: 6px;
  font-size: 12px;
  color: rgba(171, 224, 255, 0.72);
}

input,
select {
  width: 100%;
  border: 1px solid rgba(100, 201, 255, 0.16);
  border-radius: 14px;
  padding: 11px 12px;
  background: rgba(8, 31, 58, 0.76);
  color: #dff9ff;
  font: inherit;
}

select {
  color-scheme: dark;
}

select option {
  background: #0b2444;
  color: #dff9ff;
}

input[type="datetime-local"] {
  color-scheme: dark;
}

input[type="datetime-local"]::-webkit-calendar-picker-indicator {
  filter: invert(0.9) sepia(0.25) saturate(4) hue-rotate(165deg);
  cursor: pointer;
}

input[type="datetime-local"]::-webkit-datetime-edit,
input[type="datetime-local"]::-webkit-datetime-edit-fields-wrapper,
input[type="datetime-local"]::-webkit-datetime-edit-text,
input[type="datetime-local"]::-webkit-datetime-edit-month-field,
input[type="datetime-local"]::-webkit-datetime-edit-day-field,
input[type="datetime-local"]::-webkit-datetime-edit-year-field,
input[type="datetime-local"]::-webkit-datetime-edit-hour-field,
input[type="datetime-local"]::-webkit-datetime-edit-minute-field {
  color: #dff9ff;
}

.btn:focus-visible,
.tab-btn:focus-visible,
.time-range-btn:focus-visible,
.page-btn:focus-visible,
.detail-tab-btn:focus-visible,
.table-sort-btn:focus-visible,
.filter-chip:focus-visible,
.select-checkbox:focus-visible,
.priority-item:focus-visible {
  outline: 2px solid rgba(123, 215, 255, 0.64);
  outline-offset: 2px;
}

.empty,
.empty-state,
.empty-line {
  color: rgba(171, 224, 255, 0.5);
}

.evidence-panel {
  margin-top: 18px;
}

.console-modal-layer {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: rgba(2, 10, 20, 0.72);
  backdrop-filter: blur(10px);
  overscroll-behavior: contain;
}

.attack-detail-layer {
  z-index: 60;
}

.attack-payload-layer {
  z-index: 70;
}

.replay-detail-layer {
  z-index: 75;
}

.attack-confirm-layer {
  z-index: 80;
}

.attack-export-layer {
  z-index: 80;
}

.honeypot-start-layer {
  z-index: 85;
}

.console-modal {
  width: min(100%, 1120px);
  margin: 0;
  overflow: hidden;
}

.attack-detail-modal {
  height: min(820px, calc(100vh - 48px));
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
}

.attack-confirm-modal {
  width: min(100%, 480px);
  display: grid;
  gap: 18px;
}

.honeypot-start-modal {
  width: min(100%, 520px);
  display: grid;
  gap: 18px;
}

.honeypot-start-body {
  display: flex;
  gap: 16px;
  align-items: center;
}

.honeypot-start-spinner {
  width: 42px;
  height: 42px;
  flex: 0 0 auto;
  border-radius: 999px;
  border: 3px solid rgba(123, 215, 255, 0.22);
  border-top-color: rgba(123, 215, 255, 0.95);
  animation: honeypot-start-spin 0.8s linear infinite;
}

@keyframes honeypot-start-spin {
  to {
    transform: rotate(360deg);
  }
}

.attack-payload-modal {
  width: min(100%, 980px);
  height: min(680px, calc(100vh - 64px));
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
}

.replay-detail-modal {
  width: min(100%, 1080px);
  height: min(760px, calc(100vh - 56px));
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
}

.modal-body-scroll {
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  padding-right: 8px;
  overscroll-behavior: contain;
  scrollbar-gutter: stable;
}

.payload-modal-pre {
  margin: 0;
  min-height: 0;
  overflow: auto;
  overscroll-behavior: contain;
  scrollbar-gutter: stable;
}

.modal-body-scroll,
.payload-modal-pre,
.payload-preview {
  scrollbar-width: thin;
  scrollbar-color: rgba(76, 183, 255, 0.72) rgba(8, 28, 52, 0.38);
}

.modal-body-scroll::-webkit-scrollbar,
.payload-modal-pre::-webkit-scrollbar,
.payload-preview::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.modal-body-scroll::-webkit-scrollbar-track,
.payload-modal-pre::-webkit-scrollbar-track,
.payload-preview::-webkit-scrollbar-track {
  border-radius: 999px;
  background: rgba(8, 28, 52, 0.42);
}

.modal-body-scroll::-webkit-scrollbar-thumb,
.payload-modal-pre::-webkit-scrollbar-thumb,
.payload-preview::-webkit-scrollbar-thumb {
  border: 2px solid rgba(8, 28, 52, 0.28);
  border-radius: 999px;
  background: linear-gradient(180deg, rgba(90, 211, 255, 0.82), rgba(37, 126, 228, 0.82));
}

.modal-body-scroll::-webkit-scrollbar-thumb:hover,
.payload-modal-pre::-webkit-scrollbar-thumb:hover,
.payload-preview::-webkit-scrollbar-thumb:hover {
  background: linear-gradient(180deg, rgba(119, 223, 255, 0.92), rgba(55, 145, 241, 0.92));
}

.modal-copy {
  margin: 0;
  color: rgba(223, 249, 255, 0.88);
  line-height: 1.7;
}

.modal-actions {
  justify-content: flex-end;
}

@media (max-width: 1080px) {
  .panel-grid,
  .attack-stage,
  .attack-layout,
  .replay-layout,
  .replay-stage-body,
  .honeypot-kpi-grid,
  .honeypot-workbench,
  .honeypot-stage-body,
  .detail-summary-grid,
  .replay-summary-grid,
  .replay-stage-summary-grid,
  .replay-detail-summary-grid,
  .honeypot-detail-summary,
  .honeypot-create-summary,
  .honeypot-info-list,
  .honeypot-meta-grid,
  .honeypot-meta-grid-compact,
  .honeypot-detail-sections,
  .honeypot-create-form,
  .detail-pane-grid,
  .payload-preview-grid,
  .session-detail-grid,
  .evidence-stats-grid,
  .detail-grid,
  .filter-grid,
  .attack-primary-filter-row,
  .attack-advanced-filter-row {
    grid-template-columns: 1fr;
  }

  .wide {
    grid-column: span 1;
  }

  .attack-filter-card,
  .detail-card,
  .replay-workbench-card,
  .replay-inspector-card,
  .honeypot-create-card,
  .honeypot-detail-card {
    position: static;
    max-height: none;
    overflow: visible;
  }

  .event-feed li,
  .event-feed.compact li {
    grid-template-columns: 1fr;
  }

  .attack-card-head,
  .attack-list-foot {
    flex-direction: column;
    align-items: stretch;
  }

  .attack-time-row,
  .attack-time-fields {
    align-items: stretch;
  }

  .attack-ops-row {
    align-items: stretch;
  }

  .inline-select,
  .inline-select select,
  .sort-toggle {
    width: 100%;
  }

  .attack-bulk-bar {
    align-items: stretch;
  }

  .attack-time-field,
  .attack-time-field input,
  .attack-advanced-toggle {
    width: 100%;
    min-width: 0;
  }

  .replay-query-row {
    align-items: stretch;
  }

  .replay-command-row {
    align-items: stretch;
  }

  .replay-query-field {
    width: 100%;
  }

  .replay-filter-row {
    align-items: stretch;
  }

  .replay-filter-field {
    width: 100%;
  }

  .honeypot-filter-row {
    align-items: stretch;
  }

  .honeypot-filter-field {
    width: 100%;
  }

  .honeypot-instance-rail {
    padding-right: 0;
    padding-bottom: 12px;
    border-right: 0;
    border-bottom: 1px solid rgba(100, 201, 255, 0.08);
  }

  .honeypot-rail-list {
    max-height: none;
  }

  .honeypot-pane-head {
    align-items: stretch;
    flex-direction: column;
  }

  .session-card-list {
    grid-template-columns: 1fr;
  }

  .session-rail-list {
    max-height: none;
  }

  .replay-session-rail {
    padding-right: 0;
    padding-bottom: 12px;
    border-right: 0;
    border-bottom: 1px solid rgba(100, 201, 255, 0.08);
  }

  .replay-preview-feed {
    max-height: none;
  }

  .attack-detail-summary-grid {
    grid-template-areas: none;
  }

  .attack-detail-summary-grid .detail-summary-card {
    grid-area: auto;
  }

  .evidence-file-list li {
    align-items: flex-start;
  }

  .console-modal-layer {
    padding: 16px;
  }

  .attack-detail-modal,
  .attack-payload-modal,
  .replay-detail-modal {
    width: 100%;
    height: min(100vh - 32px, 100%);
  }

  .replay-drawer-toggle {
    width: 100%;
    min-width: 0;
  }
}
</style>
