// ==========================================
    // IN-MEMORY STATE (NO WEB STORAGE USAGE)
    // ==========================================
    let operatorToken = '';
    let approverToken = '';
    let networkInstance = null;
    let nodesDataSet = null;
    let edgesDataSet = null;
    let topologyInitialized = false;

    let availableFaults = [];
    let currentPreflight = null;
    let currentPipelineRun = null;
    let activeProposal = null;

    let pollIntervalMs = 2000;
    let pollTimer = null;

    const FIXED_STAGES = [
      { id: 'fault_injected', label: 'Fault Injected', source: 'LAB' },
      { id: 'telemetry_observed', label: 'Telemetry Observed', source: 'DETERMINISTIC' },
      { id: 'detected', label: 'Anomaly Detected', source: 'DETERMINISTIC' },
      { id: 'ai_analysis', label: 'AI Reasoning Analysis', source: 'AI' },
      { id: 'safety_verified', label: 'Safety Verified', source: 'SAFETY' },
      { id: 'awaiting_approval', label: 'Awaiting Human Approval', source: 'HUMAN' },
      { id: 'approved', label: 'Human Approved', source: 'HUMAN' },
      { id: 'executed', label: 'Remediation Executed', source: 'EXECUTOR' },
      { id: 'connectivity_verified', label: 'Connectivity Verified', source: 'LAB' }
    ];

    // ==========================================
    // OPERATOR AUTHENTICATION (IN-MEMORY ONLY)
    // ==========================================
    function updateToken() {
      const input = document.getElementById('operator-token');
      operatorToken = (input.value || '').trim();
      const hint = document.getElementById('token-status-hint');
      if (operatorToken) {
        hint.textContent = 'Token set in session memory (never persisted to web storage).';
        hint.style.color = '#34d399';
      } else {
        hint.textContent = 'Token cleared from session memory.';
        hint.style.color = '#94a3b8';
      }
      refreshNow();
    }

    function updateApproverToken() {
      const input = document.getElementById('approver-token');
      approverToken = (input.value || '').trim();
      const hint = document.getElementById('approver-token-status-hint');
      hint.textContent = approverToken ? 'Approver token set in page memory for this session.' : 'Approver token cleared.';
      hint.style.color = approverToken ? '#34d399' : '#94a3b8';
      fetchApprovals();
    }

    function requireToken(role='operator') {
      const input = document.getElementById(role==='approver' ? 'approver-token' : 'operator-token');
      const token = role==='approver'
        ? (approverToken || (input ? (input.value || '').trim() : ''))
        : (operatorToken || (input ? (input.value || '').trim() : ''));
      if(!token){
        if (input) {
          input.focus();
          input.scrollIntoView({behavior:'smooth',block:'center'});
        }
        alert(role==='approver'
          ? 'Enter the Human Approver Bearer Token.\n(Found in ~/.config/netops-guardrail/local-secrets.env or server output)'
          : 'Enter the Operator Bearer Token.\n(Found in ~/.config/netops-guardrail/local-secrets.env or server output)');
        return false;
      }
      if (role === 'approver') { approverToken = token; } else { operatorToken = token; }
      return true;
    }

    function getAuthHeaders(role='operator'){
      const headers = {'Content-Type': 'application/json'};
      const input = document.getElementById(role==='approver' ? 'approver-token' : 'operator-token');
      const token = role==='approver'
        ? (approverToken || (input ? (input.value || '').trim() : ''))
        : (operatorToken || (input ? (input.value || '').trim() : ''));
      if(token) headers['Authorization'] = 'Bearer ' + token;
      return headers;
    }
    // FIXED CISCO TOPOLOGY POSITIONS
    // ==========================================
    const TOPOLOGY_COORDS = {
      'h1':    { x: -380, y: 0 },
      's1':    { x: -160, y: 0 },
      's1-p1': { x: -240, y: 0 },
      's1-p2': { x: -70,  y: -75 },
      's1-p3': { x: -70,  y: 75 },

      'h2':    { x: 380,  y: 0 },
      's2':    { x: 160,  y: 0 },
      's2-p1': { x: 70,   y: -75 },
      's2-p2': { x: 70,   y: 75 },
      's2-p3': { x: 240,  y: 0 }
    };

    // ==========================================
    // DATA FETCHING & POLLING LOOP
    // ==========================================
    async function pollDashboard() {
      try {
        await Promise.all([
          fetchPreflight(),
          fetchPipelineCurrent(),
          fetchStatusAndTopology(),
          fetchApprovals()
        ]);
        pollIntervalMs = 2000; // Reset backoff on success
      } catch (err) {
        console.warn('Dashboard poll error:', err);
        pollIntervalMs = Math.min(Math.round(pollIntervalMs * 1.5), 16000);
      } finally {
        clearTimeout(pollTimer);
        pollTimer = setTimeout(pollDashboard, pollIntervalMs);
      }
    }

    function refreshNow() {
      clearTimeout(pollTimer);
      pollDashboard();
    }

    // ==========================================
    // 1. FAULTS REGISTRY
    // ==========================================
    async function loadFaults() {
      try {
        const res = await fetch('/api/pipeline/faults');
        if (!res.ok) return;
        const data = await res.json();
        availableFaults = (data.faults || []).slice();
        if (!availableFaults.some(f => /Issue\s+2/i.test(f.display_name || f.name || ''))) {
          availableFaults.push({ id: 'standby_forwarding', name: 'standby_forwarding', display_name: 'Issue 2 — Unexpected standby forwarding', description: 'Detection-only scenario: evaluates live telemetry; it does not mutate the network.', commands: ['Passive live telemetry inspection'], executable: false, live_available: false, unavailable_reason: 'Passive detection only; no live injector is configured.' });
        }
        if (!availableFaults.some(f => /Issue\s+5/i.test(f.display_name || f.name || ''))) {
          availableFaults.push({ id: 'mac_flooding', name: 'mac_flooding', display_name: 'Issue 5 — MAC table flooding', description: 'Detector exists, but a live generator is not configured.', commands: ['No live generator configured'], executable: false, live_available: false, unavailable_reason: 'Live MAC flood generator is not configured.' });
        }
        availableFaults = availableFaults.sort((a, b) => {
          const issueNumber = fault => {
            const match = String(fault.display_name || fault.name || '').match(/Issue\s+(\d+)/i);
            return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
          };
          return issueNumber(a) - issueNumber(b) ||
            String(a.display_name || a.name).localeCompare(String(b.display_name || b.name));
        });
        const select = document.getElementById('fault-select');
        select.innerHTML = '<option value="" disabled selected>-- Select a Live Fault --</option>';
        availableFaults.forEach(f => {
          const opt = document.createElement('option');
          opt.value = f.id || f.name;
          opt.disabled = false;
          opt.title = f.unavailable_reason || '';
          opt.textContent = (f.display_name || f.name) + (f.live_available === false ? ' [Not injectable]' : (f.executable ? ' [Executable]' : ' [Advisory]'));
          select.appendChild(opt);
        });
      } catch (err) {
        console.warn('Failed to load faults:', err);
      }
    }

    function onFaultSelectionChanged() {
      const select = document.getElementById('fault-select');
      const faultId = select.value;
      const fault = availableFaults.find(f => (f.id === faultId || f.name === faultId));
      if (!fault) return;

      document.getElementById('fault-target-text').textContent = fault.target || '--';
      document.getElementById('fault-desc-text').textContent = fault.description || '--';
      const cmds = Array.isArray(fault.commands) ? fault.commands.join('\n') : (fault.commands || '--');
      document.getElementById('fault-commands-preview').textContent = cmds;

      updateInjectButtonState();
    }

    function updateInjectButtonState() {
      const select = document.getElementById('fault-select');
      const btn = document.getElementById('btn-inject-fault');
      const isReady = currentPreflight && currentPreflight.ready === true;
      const selectedFault = availableFaults.find(f => (f.id === select.value || f.name === select.value));
      btn.disabled = !select.value || !isReady || selectedFault?.live_available === false;
    }

    async function injectSelectedFault() {
      if (!requireToken()) return;
      const select = document.getElementById('fault-select');
      const faultId = select.value;
      if (!faultId) return;

      const feedback = document.getElementById('injection-feedback');
      feedback.style.display = 'block';
      feedback.className = 'action-feedback';
      feedback.textContent = 'Injecting fault scenario...';

      const btn = document.getElementById('btn-inject-fault');
      btn.disabled = true;

      try {
        const res = await fetch('/api/pipeline/inject', {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify({ fault_id: faultId })
        });
        const data = await res.json();
        if (res.ok) {
          feedback.className = 'action-feedback success';
          feedback.textContent = `Fault injected successfully. Run ID: ${data.run_id || 'active'}`;
          refreshNow();
        } else {
          feedback.className = 'action-feedback error';
          feedback.textContent = `Injection failed: ${data.error || 'Server error'}`;
        }
      } catch (err) {
        feedback.className = 'action-feedback error';
        feedback.textContent = `Injection request crashed: ${err.message}`;
      } finally {
        updateInjectButtonState();
      }
    }

    // ==========================================
    // 2. LAB BASELINE RESTORE
    // ==========================================
    async function restoreLabBaseline() {
      if (!requireToken()) return;
      const feedback = document.getElementById('restore-feedback');
      feedback.style.display = 'block';
      feedback.className = 'action-feedback';
      feedback.textContent = 'Executing lab restore commands...';

      const btn = document.getElementById('btn-restore-lab');
      btn.disabled = true;

      try {
        const res = await fetch('/api/pipeline/restore', {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify({})
        });
        const data = await res.json();
        if (res.ok && data.success) {
          feedback.className = 'action-feedback success';
          feedback.textContent = `Lab restored to baseline. Completed ${data.completed_commands?.length || 0} command(s).`;
          refreshNow();
        } else {
          feedback.className = 'action-feedback error';
          feedback.textContent = `Lab restore error: ${data.error || 'Commands failed'}`;
        }
      } catch (err) {
        feedback.className = 'action-feedback error';
        feedback.textContent = `Restore request crashed: ${err.message}`;
      } finally {
        btn.disabled = false;
      }
    }

    // ==========================================
    // 3. PREFLIGHT INSPECTION
    // ==========================================
    async function fetchPreflight() {
      const res = await fetch('/api/pipeline/preflight');
      if (!res.ok) throw new Error('Preflight check failed');
      const data = await res.json();
      currentPreflight = data;

      // Update header badge
      const pBadge = document.getElementById('badge-preflight');
      const pVal = document.getElementById('val-preflight');
      if (data.ready) {
        pBadge.className = 'status-pill live';
        pVal.textContent = 'READY';
      } else {
        pBadge.className = 'status-pill stale';
        pVal.textContent = 'NOT READY';
      }

      // Update preflight card
      const summaryBadge = document.getElementById('preflight-summary-badge');
      summaryBadge.textContent = data.ready ? 'SATISFIED' : 'BLOCKED';
      summaryBadge.className = 'badge ' + (data.ready ? 'ready' : 'failed');

      // Telemetry
      const telem = data.telemetry || {};
      const telemDot = document.getElementById('pf-telemetry-dot');
      const telemVal = document.getElementById('pf-telemetry-val');
      if (telem.status === 'ok') {
        telemDot.className = 'pf-indicator ok';
        telemVal.textContent = `Fresh (${telem.age_seconds}s)`;
      } else {
        telemDot.className = 'pf-indicator error';
        telemVal.textContent = telem.status === 'stale' ? `Stale (${telem.age_seconds}s)` : telem.status.toUpperCase();
      }

      // Monitor
      const mon = data.monitor_heartbeat || {};
      const monDot = document.getElementById('pf-monitor-dot');
      const monVal = document.getElementById('pf-monitor-val');
      if (mon.status === 'ok') {
        monDot.className = 'pf-indicator ok';
        monVal.textContent = `Active (${mon.age_seconds}s)`;
      } else {
        monDot.className = 'pf-indicator error';
        monVal.textContent = mon.status === 'stale' ? `Stale (${mon.age_seconds}s)` : (mon.status || 'STOPPED').toUpperCase();
      }

      // Baseline Connectivity
      const conn = data.baseline_connectivity || {};
      const connDot = document.getElementById('pf-connectivity-dot');
      const connVal = document.getElementById('pf-connectivity-val');
      if (conn.status === 'passed') {
        connDot.className = 'pf-indicator ok';
        connVal.textContent = 'PASSED (h1⇄h2)';
      } else if (conn.status === 'unknown') {
        connDot.className = 'pf-indicator unknown';
        connVal.textContent = 'UNKNOWN';
      } else {
        connDot.className = 'pf-indicator error';
        connVal.textContent = 'FAILED';
      }

      // Active Run
      const act = data.active_run || {};
      const runDot = document.getElementById('pf-run-dot');
      const runVal = document.getElementById('pf-run-val');
      if (!act.present) {
        runDot.className = 'pf-indicator ok';
        runVal.textContent = 'None Active (Idle)';
      } else {
        runDot.className = 'pf-indicator error';
        runVal.textContent = `Active (${act.run_id || 'run'})`;
      }

      // Token Configured
      const tokDot = document.getElementById('pf-token-dot');
      const tokVal = document.getElementById('pf-token-val');
      if (data.token_configured) {
        tokDot.className = 'pf-indicator ok';
        tokVal.textContent = 'Configured in Env';
      } else {
        tokDot.className = 'pf-indicator error';
        tokVal.textContent = 'Missing NETOPS_CHAOS_API_TOKEN';
      }

      updateInjectButtonState();
    }

    // ==========================================
    // 4. PIPELINE CURRENT & TIMELINE
    // ==========================================
    async function fetchPipelineCurrent() {
      const res = await fetch('/api/pipeline/current');
      if (!res.ok) return;
      const data = await res.json();
      currentPipelineRun = data.run;

      renderPipelineTimeline(data.run, data.active);
      renderAiPanel(data.run);
      renderExecutionControls(data.run);
    }

    function renderPipelineTimeline(run, isActive) {
      const container = document.getElementById('pipeline-timeline-container');
      const runIdLabel = document.getElementById('timeline-run-id');
      const runStatusBadge = document.getElementById('timeline-run-status-badge');

      if (!run) {
        runIdLabel.textContent = 'No active remediation run';
        runStatusBadge.textContent = 'IDLE';
        runStatusBadge.className = 'badge idle';
        container.innerHTML = `
          <div class="empty-state">
            <span>No active pipeline run. Select a fault above and click <strong>Inject Fault</strong> to initiate the pipeline.</span>
          </div>
        `;
        return;
      }

      runIdLabel.textContent = `Run: ${run.run_id} · Fault: ${run.fault_id}`;
      const displayStatus = (run.outcome === 'failed') ? 'FAILED' : (run.status || (isActive ? 'ACTIVE' : 'COMPLETED'));
      runStatusBadge.textContent = displayStatus;
      runStatusBadge.className = 'badge ' + displayStatus.toLowerCase();

      const stageMap = {};
      (run.stages || []).forEach(s => { stageMap[s.name] = s; });

      let html = '';
      if (run.outcome === 'failed' && run.error) {
        html += '<div class="timeline-run-error"><strong>Run failed closed</strong><p>' + escapeHtml(run.error) + '</p><small>No remediation execution is implied by this failure state.</small></div>';
      }
      FIXED_STAGES.forEach(def => {
        const record = stageMap[def.id] || { name: def.id, status: 'PENDING', source: def.source };
        const statusClass = (record.status || 'PENDING').toLowerCase();
        const sourceTagClass = `tag-${(record.source || def.source).toLowerCase()}`;
        const timeText = record.completed_at_utc || record.started_at_utc || '--';

        html += `
          <div class="timeline-stage-card ${statusClass}">
            <div class="stage-header">
              <div class="stage-title">
                <span class="source-tag ${sourceTagClass}">${record.source || def.source}</span>
                <span>${def.label}</span>
              </div>
              <div class="stage-meta">
                <span class="stage-time">${formatUtcTime(timeText)}</span>
                <span class="badge ${statusClass}">${record.status || 'PENDING'}</span>
              </div>
            </div>
        `;

        if (record.error) {
          html += `<div class="stage-error">⚠️ ${escapeHtml(record.error)}</div>`;
        }

        if (record.evidence && Object.keys(record.evidence).length > 0) {
          html += `<div class="stage-evidence">${escapeHtml(JSON.stringify(record.evidence, null, 2))}</div>`;
        }

        html += `</div>`;
      });

      container.innerHTML = html;
    }

    function renderAiPanel(run) {
      const emptyState = document.getElementById('ai-empty-state');
      const detailsContent = document.getElementById('ai-details-content');
      const modelLabel = document.getElementById('ai-model-name');
      const verdictBadge = document.getElementById('ai-verdict-badge');
      const advisoryBanner = document.getElementById('ai-advisory-banner');

      if (!run) {
        emptyState.style.display = 'block';
        detailsContent.style.display = 'none';
        modelLabel.textContent = 'Model: Awaiting Analysis';
        verdictBadge.textContent = 'PENDING';
        verdictBadge.className = 'badge pending';
        return;
      }

      const stageMap = {};
      (run.stages || []).forEach(s => { stageMap[s.name] = s; });

      const aiStage = stageMap['ai_analysis'];
      const detStage = stageMap['detected'];
      const safetyStage = stageMap['safety_verified'];

      if (!aiStage || aiStage.status === 'PENDING') {
        emptyState.style.display = 'block';
        detailsContent.style.display = 'none';
        modelLabel.textContent = 'Model: Awaiting Analysis';
        verdictBadge.textContent = 'PENDING';
        verdictBadge.className = 'badge pending';
        return;
      }

      emptyState.style.display = 'none';
      detailsContent.style.display = 'block';

      const ev = aiStage.evidence || {};
      const modelName = ev.model || ev.model_name || 'Model not reported';
      const invoked = ev.model_invoked;
      const modelStatus = invoked === true ? ' · model invoked' : invoked === false ? ' · policy/deterministic response' : ' · invocation status unknown';
      modelLabel.textContent = `Model: ${modelName}${modelStatus}`;

      const isAdvisoryOnly = (run.executable === false) || ev.recommendation_only;
      advisoryBanner.style.display = isAdvisoryOnly ? 'block' : 'none';

      // Anomaly & evidence
      const detReason = (detStage?.evidence?.reason) || (detStage?.evidence?.detection_reason) || 'Anomaly observed in telemetry';
      document.getElementById('ai-anomaly-evidence').textContent = detReason;

      // Recommendation & rationale
      const intent = ev.intent || ev.proposed_intent || {};
      const actionText = intent.action ? intent.action.toUpperCase() : (ev.recommendation || 'NO ACTION');
      const rationaleText = intent.reason || ev.rationale || 'No model-provided rationale available.';
      document.getElementById('ai-recommendation-text').textContent = rationaleText;
      const actionEl = document.getElementById('ai-action-summary');
      if (actionEl) actionEl.textContent = actionText;
      const targetEl = document.getElementById('ai-target-summary');
      if (targetEl) targetEl.textContent = (intent.action && intent.action !== 'no_action') ? 'Switch ' + (intent.target_switch || intent.switch_id || '--') + ' · Port ' + (intent.from_port || intent.port || '--') : 'No network target (no_action)';
      const confidenceEl = document.getElementById('ai-confidence-summary');
      if (confidenceEl) confidenceEl.textContent = Number.isFinite(Number(intent.confidence)) ? Math.round(Number(intent.confidence) * 100) + '%' : 'Not reported';
      const modelStatusEl = document.getElementById('ai-model-status');
      if (modelStatusEl) modelStatusEl.textContent = ev.agent_status || 'Not reported';
      const rawEl = document.getElementById('ai-raw-output');
      if (rawEl) { const raw = ev.raw_output || ev.parsed_decision || intent; rawEl.textContent = typeof raw === 'string' ? raw : JSON.stringify(raw, null, 2); }

      // Evidence refs
      const refs = ev.evidence_refs || intent.evidence_refs || [];
      document.getElementById('ai-evidence-refs').textContent = Array.isArray(refs) && refs.length > 0 ? refs.join(', ') : 'Direct telemetry inspection';

      // Safety verdict
      const safetyEv = safetyStage?.evidence || {};
      const safetySafe = safetyEv.safe ?? (safetyStage?.status === 'COMPLETED');
      const verdictText = safetySafe ? 'PASSED (Loop-Free & Connectivity Invariants Verified)' : 'INVARIANT_VIOLATION / BLOCKED';
      document.getElementById('ai-safety-verdict-text').textContent = verdictText;

      verdictBadge.textContent = safetySafe ? 'PASSED' : 'BLOCKED';
      verdictBadge.className = 'badge ' + (safetySafe ? 'passed' : 'failed');
    }

    // ==========================================
    // 5. PROPOSALS & EXECUTION
    // ==========================================
    async function fetchApprovals() {
      if (!approverToken) return;
      try {
        const res = await fetch('/api/approvals', {
          headers: getAuthHeaders('approver')
        });
        if (!res.ok) return;
        const data = await res.json();
        const proposals = data.proposals || [];
        activeProposal = proposals.find(p => p.status === 'pending' || p.status === 'approved') || proposals[0] || null;
        renderProposalDetails(activeProposal);
      } catch (err) {
        console.warn('Approvals fetch error:', err);
      }
    }

    function renderProposalDetails(prop) {
      const box = document.getElementById('proposal-detail-box');
      const badge = document.getElementById('proposal-status-badge');
      const targetDesc = document.getElementById('proposal-target-desc');
      const btnApprove = document.getElementById('btn-approve-proposal');
      const btnReject = document.getElementById('btn-reject-proposal');
      const hint = document.getElementById('approval-disabled-hint');

      if (!prop) {
        box.style.display = 'none';
        badge.textContent = 'NONE';
        badge.className = 'badge unknown';
        if (targetDesc) targetDesc.textContent = 'No proposal pending approval';
        btnApprove.disabled = true;
        btnReject.disabled = true;
        if (hint) {
          const input = document.getElementById('approver-token');
          const hasToken = approverToken || (input && (input.value || '').trim());
          if (!hasToken) {
            hint.textContent = 'Enter Human Approver Bearer Token above to unlock pending proposals.';
            hint.style.color = '#fbbf24';
          } else {
            hint.textContent = 'Approve/Reject are enabled only when a proposal is created and its status is PENDING. Your token alone does not create a proposal.';
            hint.style.color = '#fbbf24';
          }
        }
        return;
      }

      box.style.display = 'flex';
      badge.textContent = (prop.status || 'PENDING').toUpperCase();
      badge.className = 'badge ' + (prop.status || 'pending').toLowerCase();
      const sw = prop.intent?.switch_id || prop.intent?.target_switch || '';
      const pt = prop.intent?.port || prop.intent?.from_port || '';
      if (targetDesc) targetDesc.textContent = `Target: Switch ${sw} Port ${pt}`;

      document.getElementById('prop-id-val').textContent = prop.proposal_id || '--';
      document.getElementById('prop-fingerprint-val').textContent = prop.proposal_fingerprint || '--';
      document.getElementById('prop-action-val').textContent = (prop.intent?.action || '--').toUpperCase();
      document.getElementById('prop-scope-val').textContent = (prop.intent?.action === 'block') ? 'Executable Remediation' : 'Advisory Only';

      const isPending = prop.status === 'pending';
      btnApprove.disabled = !isPending;
      btnReject.disabled = !isPending;

      if (hint) {
        if (isPending) {
          hint.textContent = 'Proposal ready for review. Enter decision reason above and click Approve or Reject.';
          hint.style.color = '#34d399';
        } else {
          hint.textContent = `Proposal is ${prop.status.toUpperCase()} (not pending).`;
          hint.style.color = '#94a3b8';
        }
      }
    }

    function renderExecutionControls(run) {
      const btnExec = document.getElementById('btn-execute-remediation');
      const btnAck = document.getElementById('btn-acknowledge-recommendation');
      const statusDesc = document.getElementById('exec-status-desc');

      if (!run) {
        btnExec.disabled = true;
        btnAck.disabled = true;
        statusDesc.textContent = 'No active pipeline run.';
        return;
      }

      const isApproved = activeProposal && activeProposal.status === 'approved';
      const isExecutable = run.executable === true;
      const needsAcknowledgement = run.status === 'RECOMMENDATION_ONLY_PENDING_ACK';
      btnAck.disabled = !needsAcknowledgement;

      if (needsAcknowledgement) {
        btnExec.disabled = true;
        statusDesc.textContent = 'AI returned action="no_action". Enter a reason below and click "Acknowledge Recommendation (No Execution)".';
        const hint = document.getElementById('approval-disabled-hint');
        if (hint && (!activeProposal || activeProposal.status !== 'pending')) {
          hint.textContent = 'AI decided on NO_ACTION (Recommendation only; no network changes were proposed). Use "Acknowledge Recommendation" below.';
          hint.style.color = '#38bdf8';
        }
      } else if (!isExecutable) {
        btnExec.disabled = true;
        statusDesc.textContent = 'Execution disabled: This fault scenario is advisory only.';
      } else if (!isApproved) {
        btnExec.disabled = true;
        statusDesc.textContent = 'Awaiting human approval before execution can be triggered.';
      } else {
        btnExec.disabled = false;
        statusDesc.textContent = 'Proposal approved! Ready to execute guarded remediation.';
      }
    }

    async function decideProposal(decision) {
      if (!requireToken('approver')) return;
      if (!activeProposal) {
        alert('No proposal available to decide.');
        return;
      }

      const reasonInput = document.getElementById('decision-reason');
      const reason = (reasonInput.value || '').trim();
      if (!reason) {
        reasonInput.focus();
        alert('A decision reason is strictly required before approving or rejecting.');
        return;
      }

      const btnA = document.getElementById('btn-approve-proposal');
      const btnR = document.getElementById('btn-reject-proposal');
      btnA.disabled = true;
      btnR.disabled = true;

      try {
        const res = await fetch(`/api/approvals/${activeProposal.proposal_id}/decision`, {
          method: 'POST',
          headers: getAuthHeaders('approver'),
          body: JSON.stringify({
            decision: decision,
            reason: reason,
            proposal_fingerprint: activeProposal.proposal_fingerprint
          })
        });
        const data = await res.json();
        if (res.ok) {
          reasonInput.value = '';
          refreshNow();
        } else {
          alert(`Decision error: ${data.error || 'Server error'}`);
        }
      } catch (err) {
        alert(`Decision request crashed: ${err.message}`);
      } finally {
        btnA.disabled = false;
        btnR.disabled = false;
      }
    }

    async function executeApprovedRemediation() {
      if (!requireToken('approver')) return;
      if (!activeProposal) return;

      const feedback = document.getElementById('exec-feedback');
      feedback.style.display = 'block';
      feedback.className = 'action-feedback';
      feedback.textContent = 'Executing approved remediation via executor...';

      const btnExec = document.getElementById('btn-execute-remediation');
      btnExec.disabled = true;

      try {
        const res = await fetch(`/api/approvals/${activeProposal.proposal_id}/execute`, {
          method: 'POST',
          headers: getAuthHeaders('approver'),
          body: JSON.stringify({})
        });
        const data = await res.json();
        if (res.ok && data.success) {
          feedback.className = 'action-feedback success';
          feedback.textContent = 'Remediation executed successfully!';

          if (data.audit_record) {
            document.getElementById('audit-proof-box').style.display = 'flex';
            document.getElementById('audit-record-id').textContent = data.audit_record.index ?? '0';
            document.getElementById('audit-current-hash').textContent = data.audit_record.current_hash || '--';
          }
          refreshNow();
        } else {
          feedback.className = 'action-feedback error';
          feedback.textContent = `Execution failed: ${data.error || 'Rejected by guardrail'}`;
        }
      } catch (err) {
        feedback.className = 'action-feedback error';
        feedback.textContent = `Execution request crashed: ${err.message}`;
      } finally {
        btnExec.disabled = false;
      }
    }

    async function acknowledgeRecommendation() {
      if (!requireToken('approver')) return;
      const reasonInput = document.getElementById('recommendation-ack-reason');
      const reason = (reasonInput.value || '').trim();
      if (!reason) {
        reasonInput.focus();
        alert('A reason is required to acknowledge this recommendation.');
        return;
      }

      const button = document.getElementById('btn-acknowledge-recommendation');
      const feedback = document.getElementById('exec-feedback');
      button.disabled = true;
      feedback.style.display = 'block';
      feedback.className = 'action-feedback';
      feedback.textContent = 'Recording human acknowledgement; no network command will be executed.';

      try {
        const res = await fetch('/api/pipeline/acknowledge', {
          method: 'POST',
          headers: getAuthHeaders('approver'),
          body: JSON.stringify({ reason })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          feedback.className = 'action-feedback success';
          feedback.textContent = 'Recommendation acknowledged. Executor was not called.';
          reasonInput.value = '';
          await refreshNow();
        } else {
          feedback.className = 'action-feedback error';
          feedback.textContent = 'Acknowledgement failed: ' + (data.error || 'Request rejected');
        }
      } catch (err) {
        feedback.className = 'action-feedback error';
        feedback.textContent = 'Acknowledgement request failed: ' + err.message;
      } finally {
        button.disabled = false;
      }
    }

    // ==========================================
    // 6. TOPOLOGY & HONEST SYSTEM STATUS
    // ==========================================
    async function fetchStatusAndTopology() {
      const res = await fetch('/api/status');
      if (!res.ok) throw new Error('Status fetch failed');
      const data = await res.json();

      const telem = data.telemetry || {};
      const monitor = data.monitor || {};

      renderHonestSystemStatus(telem, monitor);
      renderIncidentMonitor(data.incidents || [], monitor);
      renderTopology(telem);
    }

    function renderIncidentMonitor(incidents, monitor) {
      const list = document.getElementById('incident-list');
      const state = document.getElementById('incident-monitor-state');
      const summary = document.getElementById('incident-monitor-summary');
      if (!list || !state) return;
      const active = (incidents || []).filter(item =>
        !['RESOLVED', 'CLOSED'].includes(String(item.state || '').toUpperCase()));
      const heartbeat = monitor.last_heartbeat_utc
        ? new Date(monitor.last_heartbeat_utc).toLocaleTimeString() : 'not available';
      const scanTime = monitor.last_scan_utc
        ? new Date(monitor.last_scan_utc).toLocaleTimeString() : 'waiting for first scan';
      const scanCount = Number(monitor.last_detection_count || 0);
      state.textContent = monitor.status === 'running' || monitor.status === 'degraded'
        ? 'Monitoring ' + monitor.status.toUpperCase() + ' · last scan ' + scanTime
        : 'Monitor offline';
      if (summary) summary.textContent = 'Heartbeat ' + heartbeat + ' · ' + scanCount +
        ' detection(s) in last scan · AI ' + (monitor.ai_enabled ? 'enabled' : 'disabled') +
        ' · ' + (monitor.last_scan_summary || 'No scan summary yet');
      if (!incidents.length) {
        list.innerHTML = '<div class="monitor-empty"><strong>No persisted incidents</strong><p>' +
          escapeHtml(monitor.last_scan_summary || 'Waiting for the first telemetry scan.') +
          '</p><small>Last scan: ' + escapeHtml(scanTime) + ' · Heartbeat: ' +
          escapeHtml(heartbeat) + '</small></div>';
        return;
      }
      const recent = incidents.slice().sort((a, b) =>
        (Date.parse(b.observed_at_utc || '') || 0) - (Date.parse(a.observed_at_utc || '') || 0)
      ).slice(0, 6);
      list.innerHTML = recent.map(item => {
        const stateText = String(item.state || 'UNKNOWN');
        const activeClass = active.includes(item) ? 'incident-active' : 'incident-resolved';
        const title = String(item.type || 'Incident').replace(/_/g, ' ');
        const evidence = item.evidence || {};
        const reason = evidence.reason || evidence.result?.reason || item.ai_decision?.reason ||
          'Evidence recorded; see incident details.';
        return '<article class="incident-item ' + activeClass + '">' +
          '<div class="incident-item-head"><strong>' + escapeHtml(title) + '</strong><span class="incident-state">' +
          escapeHtml(stateText) + '</span></div><p>' + escapeHtml(reason) + '</p><small>' +
          escapeHtml(item.observed_at_utc || '') + ' · ID ' + escapeHtml(item.incident_id || '') +
          '</small></article>';
      }).join('');
    }

    function renderHonestSystemStatus(telem, monitor) {
      // 1. Telemetry Freshness
      const tBadge = document.getElementById('badge-telemetry');
      const tVal = document.getElementById('val-telemetry');
      if (telem.updated_at_utc) {
        const age = Math.max(0, Math.round((Date.now() - new Date(telem.updated_at_utc).getTime()) / 1000));
        if (age <= 30) {
          tBadge.className = 'status-pill live';
          tVal.textContent = `Live (${age}s ago)`;
        } else {
          tBadge.className = 'status-pill stale';
          tVal.textContent = `STALE (${age}s ago)`;
        }
      } else {
        tBadge.className = 'status-pill unknown';
        tVal.textContent = 'UNKNOWN';
      }

      // 2. Monitor Heartbeat
      const mBadge = document.getElementById('badge-monitor');
      const mVal = document.getElementById('val-monitor');
      if (monitor.status === 'running' || monitor.status === 'degraded') {
        const age = monitor.heartbeat_age_seconds ?? 0;
        mBadge.className = 'status-pill live';
        mVal.textContent = `Active (${age}s ago)`;
      } else {
        mBadge.className = 'status-pill error';
        mVal.textContent = 'STOPPED';
      }

      // 3. Baseline Connectivity
      const cBadge = document.getElementById('badge-connectivity');
      const cVal = document.getElementById('val-connectivity');
      if (currentPreflight && currentPreflight.baseline_connectivity) {
        const cStatus = currentPreflight.baseline_connectivity.status;
        if (cStatus === 'passed') {
          cBadge.className = 'status-pill live';
          cVal.textContent = 'Passed';
        } else if (cStatus === 'failed') {
          cBadge.className = 'status-pill error';
          cVal.textContent = 'FAILED';
        } else {
          cBadge.className = 'status-pill unknown';
          cVal.textContent = 'UNKNOWN';
        }
      } else {
        cBadge.className = 'status-pill unknown';
        cVal.textContent = 'UNKNOWN';
      }
    }

    function renderTopology(telem) {
      const loader = document.getElementById('topo-loader');
      if (loader) loader.style.display = 'none';
      const staleBanner = document.getElementById('stale-telemetry-banner');
      const topoTag = document.getElementById('topo-state-tag');
      let isStale = true;
      if (telem.updated_at_utc) {
        const age = (Date.now() - new Date(telem.updated_at_utc).getTime()) / 1000;
        isStale = age > 30;
      }
      staleBanner.style.display = isStale ? 'block' : 'none';
      topoTag.textContent = isStale ? 'STALE' : 'LIVE';
      topoTag.className = 'badge ' + (isStale ? 'stale' : 'ready');

      const switches = telem.switches || {};
      const s1 = switches['1'] || {};
      const s2 = switches['2'] || {};
      const s1Stp = s1.stp_port_states || {};
      const s2Stp = s2.stp_port_states || {};
      const getStpState = (sw, port) => String((sw === '1' ? s1Stp : s2Stp)[String(port)] || 'UNKNOWN').toUpperCase();
      const stateColor = state => {
        if (['FORWARD','FORWARDING'].includes(state)) return '#27d987';
        if (['BLOCK','BLOCKED'].includes(state)) return '#f6ad3c';
        if (['LEARN','LEARNING'].includes(state)) return '#32c7e8';
        if (['DOWN','DISABLE','DISABLED'].includes(state)) return '#f15b64';
        return '#8996a8';
      };
      const p = {
        s1p1:getStpState('1',1), s1p2:getStpState('1',2), s1p3:getStpState('1',3),
        s2p1:getStpState('2',1), s2p2:getStpState('2',2), s2p3:getStpState('2',3)
      };
      const hosts = telem.hosts || [];
      const h1Active = hosts.some(h=>h.switch_id==='1'&&h.port_id==='1');
      const h2Active = hosts.some(h=>h.switch_id==='2'&&h.port_id==='3');
      const primaryBlocked = ['BLOCK','BLOCKED'].includes(p.s1p2)||['BLOCK','BLOCKED'].includes(p.s2p1);
      const backupBlocked = ['BLOCK','BLOCKED'].includes(p.s1p3)||['BLOCK','BLOCKED'].includes(p.s2p2);
      const primaryColor = primaryBlocked ? '#f6ad3c' : '#27d987';
      const backupColor = backupBlocked ? '#f6ad3c' : '#27d987';
      const portPill=(x,y,id,iface,state)=>`<g class="port-pill"><rect x="${x}" y="${y}" width="126" height="44" rx="11" fill="#111d2b" stroke="${stateColor(state)}" stroke-width="2"/><text x="${x+63}" y="${y+17}" text-anchor="middle" class="port-iface">${iface}</text><text id="topo-${id}" x="${x+63}" y="${y+34}" text-anchor="middle" class="port-state" fill="${stateColor(state)}">${state}</text></g>`;
      const pc=(x,label,ip,active)=>`<g transform="translate(${x},220)" class="device"><rect x="0" y="10" width="104" height="82" rx="7" fill="#192430" stroke="#718096" stroke-width="3"/><rect x="9" y="19" width="86" height="62" rx="3" fill="#0a1728" stroke="#475569"/><rect x="12" y="22" width="80" height="56" fill="url(#screenGlow)"/><path d="M18 67 L40 48 L54 58 L74 35 L89 55" fill="none" stroke="#49b7ed" stroke-width="2.5" opacity=".65"/><rect x="43" y="92" width="18" height="10" fill="#7d8998"/><path d="M25 103 H80 L88 110 H17 Z" fill="#8995a3" stroke="#475569"/><rect x="-13" y="52" width="14" height="68" rx="3" fill="#252f3b" stroke="#64748b"/><rect x="-7" y="61" width="2" height="42" fill="#64748b"/><circle cx="-5" cy="112" r="2.5" fill="#27d987"/><text x="48" y="140" text-anchor="middle" class="device-title">${label}</text><text x="48" y="158" text-anchor="middle" class="device-sub">${ip}</text><text x="48" y="177" text-anchor="middle" class="host-state" fill="${active?'#27d987':'#aab4c1'}">${active?'● ACTIVE':'○ NOT OBSERVED'}</text></g>`;
      const sw=(x,label)=>`<g transform="translate(${x},230)" class="device"><rect x="0" y="0" width="245" height="88" rx="9" fill="#142232" stroke="#4d6e91" stroke-width="3"/><rect x="9" y="9" width="227" height="70" rx="5" fill="#1c2d3f" stroke="#2c4867"/><text x="18" y="26" class="switch-brand">NETWORK SWITCH</text><g transform="translate(18,35)">${Array.from({length:12},(_,i)=>`<rect x="${i*16}" y="0" width="12" height="15" rx="2" fill="#08131e" stroke="#4b6177"/><rect x="${i*16+2}" y="2" width="8" height="11" fill="#243e52"/>`).join('')}</g><circle cx="220" cy="62" r="4" fill="#27d987"/><text x="122" y="108" text-anchor="middle" class="device-title">${label}</text><text x="122" y="126" text-anchor="middle" class="device-sub">OpenFlow 1.3 · OVS</text></g>`;
      const container=document.getElementById('topology-canvas');
      container.innerHTML=`<svg id="static-topology-svg" class="static-topology" viewBox="0 0 1200 560" role="img" aria-label="Fixed network topology with two hosts and two switches">
        <defs><pattern id="topoGrid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" stroke="#293744" stroke-width=".7"/></pattern><linearGradient id="screenGlow" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#13395d"/><stop offset="1" stop-color="#0b1724"/></linearGradient><filter id="softGlow"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
        <rect width="1200" height="560" rx="14" fill="#0d1722"/><rect width="1200" height="560" fill="url(#topoGrid)" opacity=".7"/>
        <text x="600" y="40" text-anchor="middle" class="topo-title">TOPOLOGY OVERVIEW</text><circle cx="760" cy="32" r="5" fill="${isStale?'#f6ad3c':'#27d987'}"/>
        <!-- cables behind devices -->
        <path d="M190 300 H310" stroke="#d5a54a" stroke-width="5" fill="none"/><path d="M890 300 H1010" stroke="#d5a54a" stroke-width="5" fill="none"/>
        <path d="M555 250 C575 165 625 165 645 250" stroke="${primaryColor}" stroke-width="6" fill="none" stroke-linecap="round"/><path d="M555 315 C575 405 625 405 645 315" stroke="${backupColor}" stroke-width="6" fill="none" stroke-linecap="round"/>
        <text x="600" y="145" text-anchor="middle" class="link-label" fill="${primaryColor}">PRIMARY TRUNK · ${p.s1p2} / ${p.s2p1}</text><text x="600" y="430" text-anchor="middle" class="link-label" fill="${backupColor}">STANDBY TRUNK · ${p.s1p3} / ${p.s2p2}</text>
        <text x="245" y="280" text-anchor="middle" class="link-label" fill="#d5a54a">ACCESS</text><text x="950" y="280" text-anchor="middle" class="link-label" fill="#d5a54a">ACCESS</text>
        ${pc(80,'Host h1','10.0.0.1 / h1-eth0',h1Active)} ${pc(1015,'Host h2','10.0.0.2 / h2-eth0',h2Active)}
        ${sw(310,'Switch s1 · Catalyst 2960')} ${sw(645,'Switch s2 · Catalyst 2960')}
        ${portPill(285,345,'s1p1','s1-eth1 · port 1',p.s1p1)} ${portPill(430,170,'s1p2','s1-eth2 · port 2',p.s1p2)} ${portPill(430,365,'s1p3','s1-eth3 · port 3',p.s1p3)}
        ${portPill(645,170,'s2p1','s2-eth1 · port 1',p.s2p1)} ${portPill(645,365,'s2p2','s2-eth2 · port 2',p.s2p2)} ${portPill(770,345,'s2p3','s2-eth3 · port 3',p.s2p3)}
      </svg>`;
    }
    // ==========================================
    // LIFECYCLE EVALUATION FOR TOPOLOGY BADGE
    // ==========================================
    function approvalInfoForTrace(record) {
      return record?.human_approval ||
        record?.audit_record?.execution_result?.human_approval ||
        {};
    }

    function applyTopologyStatus(record) {
      const panel = document.getElementById('panel-topology');
      const tintBadge = document.getElementById('tint-badge');
      if (!record || !panel || !tintBadge) return;

      const approval = approvalInfoForTrace(record);
      const decision = String(record.decision || '').toUpperCase();
      const approvalStatus = String(approval.status || '').toLowerCase();
      const execution = record.execution ||
        record.audit_record?.execution_result?.execution ||
        record.execution_result || {};
      const executionSucceeded = execution.success === true ||
        ['success', 'succeeded'].includes(String(execution.status || '').toLowerCase());

      const setState = (panelClass, badgeClass, label, explanation) => {
        tintBadge.style.display = 'inline-flex';
        tintBadge.className = 'badge ' + badgeClass;
        tintBadge.textContent = label;
        tintBadge.title = explanation;
      };

      if (executionSucceeded) {
        setState('tint-executed', 'ready', '● REMEDIATION: EXECUTED',
          'Remediation has executed successfully on the data plane.');
        return;
      }

      const isExpired = approvalStatus === 'expired' ||
        (approval.expires_at_utc && Date.now() > new Date(approval.expires_at_utc).getTime());

      if (approvalStatus === 'pending' || (decision === 'PENDING_HUMAN_APPROVAL' && !isExpired)) {
        setState('tint-pending', 'pending',
          '● HUMAN APPROVAL: PENDING (' + (approval.action || record.action || 'REVIEW') + ')',
          isExpired
            ? 'This proposal has expired and cannot be approved for execution.'
            : 'Safety checks are separate from approval. A human decision is still required; remediation has not executed.');
        return;
      }

      if (decision === 'REJECTED' || approvalStatus === 'rejected') {
        setState('tint-unsafe', 'failed', '● HUMAN DECISION: REJECTED',
          'The human reviewer rejected this proposal. It must not be executed.');
        return;
      }

      if (decision === 'CHANGES_REQUESTED' || approvalStatus === 'changes_requested') {
        setState('tint-pending', 'pending', '● HUMAN REVIEW: CHANGES REQUESTED',
          'The reviewer requested changes. This proposal has not been authorized for execution.');
        return;
      }

      if (decision === 'APPROVED' || approvalStatus === 'approved') {
        setState('tint-human-approved', 'ready',
          '● HUMAN APPROVAL: APPROVED · NOT EXECUTED',
          'Approval was recorded, but that alone does not mean remediation executed successfully.');
        return;
      }

      const safe = record.verification?.safe ??
        record.audit_record?.verifier_result?.safe;
      if (safe === true) {
        setState('tint-safe', 'ready', '● SAFETY CHECK: PASS',
          'Automated safety verification passed. This is not human approval or execution status.');
      } else if (safe === false) {
        setState('tint-unsafe', 'failed', '● SAFETY CHECK: FAIL (BLOCKED)',
          'Automated safety verification failed; remediation should remain blocked.');
      } else {
        setState('', 'unknown', '● STATUS: NOT AVAILABLE',
          'No safety, human approval, or execution result is available in the latest trace record.');
      }
    }

    async function updateTraceRecords(records) {
      if (!records || !records.length) return;
      const chronological = records.slice().sort((a, b) => {
        const aTime = Date.parse(a.timestamp || '') || 0;
        const bTime = Date.parse(b.timestamp || '') || 0;
        return aTime - bTime;
      });
      const lifecycleRecords = chronological.filter(item =>
        Boolean(approvalInfoForTrace(item).proposal_id)
      );
      const latest = lifecycleRecords.length
        ? lifecycleRecords[lifecycleRecords.length - 1]
        : chronological[chronological.length - 1];
      if (latest) applyTopologyStatus(latest);
    }

    function formatTraceProposalMeta(approval) {
      if (approval && approval.proposal_id) {
        return 'Proposal ID: ' + approval.proposal_id;
      }
      return '';
    }

    // ==========================================
    // UTILITY HELPERS
    // ==========================================
    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function formatUtcTime(iso) {
      if (!iso || iso === '--') return '--';
      try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      } catch (e) {
        return iso;
      }
    }

    // ==========================================
    // INITIALIZATION
    // ==========================================
    document.addEventListener('DOMContentLoaded', () => {
      const opInput = document.getElementById('operator-token');
      if (opInput) {
        opInput.addEventListener('input', () => {
          operatorToken = (opInput.value || '').trim();
        });
        opInput.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') updateToken();
        });
      }
      const apInput = document.getElementById('approver-token');
      if (apInput) {
        apInput.addEventListener('input', () => {
          approverToken = (apInput.value || '').trim();
          if (approverToken) fetchApprovals();
        });
        apInput.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') updateApproverToken();
        });
      }
      loadFaults();
      pollDashboard();
    });