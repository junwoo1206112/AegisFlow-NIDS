const state = { events: [], metrics: null, severity: "", connected: false };
const colors = ["#ff5067", "#ff9f43", "#29e7d7", "#a7ef63", "#9d7cff", "#ffd166"];
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
function formatNumber(value) { return new Intl.NumberFormat("ko-KR").format(value || 0); }
function formatTime(value) { return new Date(value).toLocaleTimeString("ko-KR", {hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit"}); }
function showToast(message) { const el=$("#toast"); el.textContent=message; el.classList.add("show"); setTimeout(()=>el.classList.remove("show"),2400); }

async function api(path, options = {}) {
  const response = await fetch(path, {headers:{"Content-Type":"application/json"}, ...options});
  if (!response.ok) throw new Error(`API ${response.status}`);
  return response.json();
}

function renderSparks() {
  for (const [id, base] of [["#flowSpark", 14], ["#alertSpark", 7]]) {
    $(id).innerHTML = Array.from({length:14}, (_,i)=>`<i style="height:${Math.max(3, base + Math.sin(i*1.7)*7 + Math.random()*8)}px"></i>`).join("");
  }
}

function renderMetrics(metrics) {
  state.metrics = metrics;
  $("#totalFlows").textContent = formatNumber(metrics.total_flows);
  $("#totalAlerts").textContent = formatNumber(metrics.total_alerts);
  $("#criticalAlerts").textContent = formatNumber(metrics.critical_alerts);
  $("#lastHour").textContent = formatNumber(metrics.alerts_last_hour);
  $("#averageRisk").textContent = metrics.average_risk.toFixed(1);
  $("#riskGauge").style.width = `${Math.min(metrics.average_risk,100)}%`;
  $("#donutTotal").textContent = formatNumber(metrics.total_alerts);
  renderDistribution(metrics.by_attack_type);
  renderTimeline(metrics.timeline);
  renderSparks();
}

function renderDistribution(items) {
  const entries = Object.entries(items).slice(0,6);
  const total = entries.reduce((sum,[,count])=>sum+count,0);
  if (!total) { $("#threatLegend").innerHTML='<p class="empty">Waiting for telemetry…</p>'; return; }
  let cursor=0; const stops=[];
  entries.forEach(([,count],index)=>{ const start=cursor; cursor += count/total*100; stops.push(`${colors[index]} ${start}% ${cursor}%`); });
  $("#threatDonut").style.background=`conic-gradient(${stops.join(",")})`;
  $("#threatLegend").innerHTML=entries.map(([name,count],index)=>`<p><i style="background:${colors[index]}"></i><span>${escapeHtml(name)}</span><b>${Math.round(count/total*100)}%</b></p>`).join("");
}

function renderTimeline(timeline) {
  const points = Array(25).fill(0);
  timeline.slice(-25).forEach((item,index)=>{ points[25-timeline.slice(-25).length+index]=item.count; });
  const max=Math.max(12,...points); const coords=points.map((value,index)=>[index*(800/24),215-(value/max)*195]);
  const line=coords.map((point,index)=>`${index?'L':'M'}${point[0].toFixed(1)} ${point[1].toFixed(1)}`).join(" ");
  $("#timelineLine").setAttribute("d",line); $("#timelineArea").setAttribute("d",`${line} L800 215 L0 215 Z`);
}

function severityColor(severity) { return ({critical:"#ff5067",high:"#ff9f43",medium:"#ffd166",low:"#29e7d7"})[severity] || "#718188"; }
function renderEvents() {
  const filtered = state.events.filter(event => !state.severity || event.detection.severity === state.severity).slice(0,50);
  if (!filtered.length) { $("#eventTable").innerHTML='<tr class="loading-row"><td colspan="8">No alerts match this filter.</td></tr>'; return; }
  $("#eventTable").innerHTML=filtered.map(event=>{
    const d=event.detection,f=event.flow,color=severityColor(d.severity);
    return `<tr data-id="${event.id}"><td>${formatTime(event.created_at)}</td><td><span class="severity ${d.severity}">${d.severity}</span></td><td class="threat-name">${escapeHtml(d.attack_type)}</td><td class="ip">${escapeHtml(f.src_ip)} → ${escapeHtml(f.dst_ip)}:${f.dst_port}</td><td><span class="protocol">${f.protocol}</span></td><td><span class="risk-score"><b>${d.risk_score.toFixed(1)}</b><i style="--risk:${d.risk_score}%;--risk-color:${color}"></i></span></td><td><select class="status-select" data-status-id="${event.id}" aria-label="이벤트 상태"><option value="new" ${event.status==='new'?'selected':''}>NEW</option><option value="investigating" ${event.status==='investigating'?'selected':''}>INVESTIGATING</option><option value="resolved" ${event.status==='resolved'?'selected':''}>RESOLVED</option></select></td><td><button class="detail-btn" data-detail-id="${event.id}" aria-label="상세 보기">↗</button></td></tr>`;
  }).join("");
}

function openEvent(id) {
  const event=state.events.find(item=>item.id===id); if(!event)return;
  const d=event.detection,f=event.flow;
  $("#dialogContent").innerHTML=`<div class="dialog-kicker">EVENT #${event.id} / ${escapeHtml(d.model_version)}</div><h2 class="dialog-title">${escapeHtml(d.attack_type)}</h2><div class="dialog-grid"><div class="dialog-stat"><span>RISK SCORE</span><b style="color:${severityColor(d.severity)}">${d.risk_score} / 100</b></div><div class="dialog-stat"><span>ANOMALY</span><b>${(d.anomaly_score*100).toFixed(1)}%</b></div><div class="dialog-stat"><span>CONFIDENCE</span><b>${(d.confidence*100).toFixed(1)}%</b></div><div class="dialog-stat"><span>SOURCE</span><b>${escapeHtml(f.src_ip)}</b></div><div class="dialog-stat"><span>DESTINATION</span><b>${escapeHtml(f.dst_ip)}:${f.dst_port}</b></div><div class="dialog-stat"><span>FLOW</span><b>${formatNumber(f.packets)} pkt / ${formatNumber(f.bytes_total)} B</b></div></div><div class="explanation"><h3>Decision evidence</h3><ul>${d.explanation.map(reason=>`<li>${escapeHtml(reason)}</li>`).join("")}</ul></div>`;
  $("#eventDialog").showModal();
}

async function updateStatus(id,status) {
  try { const updated=await api(`/api/events/${id}/status`,{method:"PATCH",body:JSON.stringify({status})}); const index=state.events.findIndex(e=>e.id===id); if(index>=0)state.events[index]=updated; showToast(`Event #${id} → ${status}`); }
  catch { showToast("상태 업데이트에 실패했습니다."); await loadData(); }
}

async function loadData() {
  try {
    const [metrics,events]=await Promise.all([api("/api/metrics"),api("/api/events?limit=100&alerts_only=true")]);
    state.events=events; renderMetrics(metrics); renderEvents();
  } catch(error) { $("#eventTable").innerHTML='<tr class="loading-row"><td colspan="8">Telemetry API unavailable. Start the FastAPI server.</td></tr>'; }
}

function connectStream() {
  const protocol=location.protocol==='https:'?'wss':'ws'; const socket=new WebSocket(`${protocol}://${location.host}/ws/events`);
  socket.onopen=()=>{state.connected=true};
  socket.onmessage=message=>{ const event=JSON.parse(message.data); const index=state.events.findIndex(e=>e.id===event.id); if(index>=0)state.events[index]=event; else if(event.detection.is_alert)state.events.unshift(event); state.events=state.events.slice(0,100); renderEvents(); if(event.detection.is_alert) loadMetricsOnly(); };
  socket.onclose=()=>{state.connected=false;setTimeout(connectStream,2500)};
}
async function loadMetricsOnly(){try{renderMetrics(await api("/api/metrics"))}catch{}}

document.addEventListener("click",event=>{
  const detail=event.target.closest("[data-detail-id]"); if(detail)openEvent(Number(detail.dataset.detailId));
  if(event.target.matches(".dialog-close"))$("#eventDialog").close();
  const filter=event.target.closest(".filter"); if(filter){$$('.filter').forEach(el=>el.classList.remove('active'));filter.classList.add('active');state.severity=filter.dataset.severity;renderEvents();}
});
document.addEventListener("change",event=>{if(event.target.matches("[data-status-id]"))updateStatus(Number(event.target.dataset.statusId),event.target.value)});
$("#refreshButton").addEventListener("click",()=>{loadData();showToast("Telemetry refreshed")});
setInterval(()=>{$("#clock").textContent=new Date().toLocaleTimeString("ko-KR",{hour12:false,timeZone:"Asia/Seoul"})},1000);
setInterval(loadMetricsOnly,10000);
loadData(); connectStream();

