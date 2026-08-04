"use client";

import { FormEvent, ReactNode, useCallback, useEffect, useState } from "react";
import {
  AuthorizedRange,
  DiscoveredAsset,
  EngineStatus,
  ImportPreview,
  ScanExecution,
  ScanSchedule,
  ScannerProfile,
  Summary,
  VulnerabilityFinding,
  formatDate,
  scannerRequest,
  shortId,
} from "./scanner-api";

type ScannerPage = "scanners" | "scan-schedules" | "scan-runs" | "scan-assets";
type Tone = "ok" | "info" | "warn" | "danger" | "muted";

function Dot({ tone = "muted" }: { tone?: Tone }) {
  return <i className={`dot ${tone}`} aria-hidden="true" />;
}

function Badge({ children, tone = "muted" }: { children: ReactNode; tone?: Tone }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

function Header({ kicker, title, copy, actions }: { kicker: string; title: string; copy: string; actions?: ReactNode }) {
  return <header className="page-head"><div><span className="kicker">{kicker}</span><h1>{title}</h1><p>{copy}</p></div>{actions && <div className="head-actions">{actions}</div>}</header>;
}

function Empty({ title, copy }: { title: string; copy: string }) {
  return <div className="empty"><span>◇</span><h2>{title}</h2><p>{copy}</p></div>;
}

function ErrorNotice({ message, retry }: { message: string | null; retry?: () => void }) {
  if (!message) return null;
  return <div className="notice"><Dot tone="danger" /><span><strong>Não foi possível concluir</strong><p>{message}</p></span>{retry && <button className="btn ghost" onClick={retry}>Tentar novamente</button>}</div>;
}

function Tabs({ items, active, setActive }: { items: string[]; active: string; setActive: (tab: string) => void }) {
  return <div className="tabs">{items.map(item => <button key={item} onClick={() => setActive(item)} className={active === item ? "active" : ""}>{item}</button>)}</div>;
}

function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    queued: "Na fila",
    running: "Em execução",
    completed: "Concluído",
    partially_completed: "Parcial",
    failed: "Falha",
    cancelled: "Cancelado",
  };
  return labels[status] ?? status;
}

function statusTone(status: string): Tone {
  if (["completed", "active", "synchronized"].includes(status)) return "ok";
  if (["failed", "critical", "inactive"].includes(status)) return "danger";
  if (["partially_completed", "pending", "paused"].includes(status)) return "warn";
  if (["queued", "running"].includes(status)) return "info";
  return "muted";
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("pt-BR").format(value);
}

function usePolling<T>(path: string, interval = 10000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(async () => {
    try {
      const result = await scannerRequest<T>(path);
      setData(result);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Falha inesperada.");
    } finally {
      setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const timer = window.setInterval(() => void refresh(), interval);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [interval, refresh]);
  return { data, error, loading, refresh };
}

function RangeManager({ ranges, onClose, onChanged }: { ranges: AuthorizedRange[]; onClose: () => void; onChanged: () => Promise<void> | void }) {
  const [mode, setMode] = useState("Cadastrar faixa");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);

  async function createRange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(null);
    try {
      await scannerRequest<AuthorizedRange>("ranges", {
        method: "POST",
        body: JSON.stringify({
          name: form.get("name"),
          cidr: form.get("cidr"),
          environment: form.get("environment"),
          owner: form.get("owner"),
          description: form.get("description") || null,
          authorization_reference: form.get("authorization_reference"),
          allow_public: false,
        }),
      });
      await onChanged();
      onClose();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Falha ao cadastrar faixa.");
    } finally { setBusy(false); }
  }

  async function previewFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(null);
    try {
      setPreview(await scannerRequest<ImportPreview>("ranges/import/preview", { method: "POST", body: form }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Falha ao validar arquivo.");
    } finally { setBusy(false); }
  }

  async function confirmImport() {
    if (!preview) return;
    setBusy(true); setError(null);
    try {
      await scannerRequest<AuthorizedRange[]>("ranges/import/confirm", { method: "POST", body: JSON.stringify({ batch_id: preview.batch_id }) });
      await onChanged();
      onClose();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Falha ao confirmar importação.");
    } finally { setBusy(false); }
  }

  async function toggleRange(item: AuthorizedRange) {
    setBusy(true); setError(null);
    try {
      await scannerRequest(`ranges/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !item.enabled }) });
      await onChanged();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Falha ao atualizar faixa.");
    } finally { setBusy(false); }
  }

  return <div className="scrim" onMouseDown={onClose}><aside className="drawer scan-drawer" onMouseDown={event => event.stopPropagation()}><div className="drawer-head"><div><span className="kicker">ESCOPO AUTORIZADO</span><h2>Gerenciar faixas</h2></div><button onClick={onClose}>×</button></div><Tabs items={["Cadastrar faixa", "Importar arquivo", "Faixas cadastradas"]} active={mode} setActive={setMode} /><div className="drawer-body"><ErrorNotice message={error} />
    {mode === "Cadastrar faixa" && <form id="range-form" onSubmit={createRange}><label className="field"><span>Nome da faixa</span><input name="name" required /></label><label className="field"><span>IP ou bloco CIDR</span><input name="cidr" placeholder="10.42.16.0/24" required /></label><div className="form-pair"><label className="field"><span>Ambiente</span><input name="environment" required /></label><label className="field"><span>Responsável</span><input name="owner" required /></label></div><label className="field"><span>Descrição</span><textarea name="description" rows={3} /></label><label className="field"><span>Referência formal da autorização</span><input name="authorization_reference" placeholder="Processo, chamado ou documento" required /></label><div className="authorized-card"><Badge tone="ok">Scope Safety ativo</Badge><p>O worker revalida o CIDR antes de cada motor e rejeita qualquer resultado fora dessa faixa.</p></div></form>}
    {mode === "Importar arquivo" && !preview && <form id="import-form" onSubmit={previewFile}><label className="field"><span>Arquivo de IPs</span><input name="file" type="file" accept=".txt,.csv,.xlsx,.pdf,.zip" required /></label><div className="form-pair"><label className="field"><span>Ambiente</span><input name="environment" required /></label><label className="field"><span>Responsável</span><input name="owner" required /></label></div><label className="field"><span>Referência formal da autorização</span><input name="authorization_reference" required /></label><div className="schedule-note"><Dot tone="info" /><span><strong>Validação antes da gravação</strong><small>TXT, CSV, XLSX, PDF textual ou ZIP. Duplicidades, sobreposições e inválidos aparecem na prévia.</small></span></div></form>}
    {mode === "Importar arquivo" && preview && <div><div className="result-metrics">{[["Identificados",preview.total],["Válidos",preview.valid],["Inválidos",preview.invalid],["Duplicados",preview.duplicates],["Sobrepostos",preview.overlaps]].map(item => <div key={item[0]}><span>{item[0]}</span><strong>{item[1]}</strong></div>)}</div><div className="changes-feed">{preview.items.slice(0,100).map((item,index) => <article key={`${item.original}-${index}`}><Dot tone={item.valid ? "ok" : item.duplicate || item.overlap_with ? "warn" : "danger"} /><span><strong className="mono">{item.normalized || item.original}</strong><p>{item.valid ? "Pronto para importar" : item.error}</p></span></article>)}</div></div>}
    {mode === "Faixas cadastradas" && (ranges.length ? <div className="changes-feed">{ranges.map(item => <article key={item.id}><Dot tone={item.enabled ? "ok" : "muted"} /><span><strong>{item.name}</strong><p className="mono">{item.cidr} · {item.owner}</p></span><button className="btn ghost" disabled={busy} onClick={() => void toggleRange(item)}>{item.enabled ? "Desativar" : "Ativar"}</button></article>)}</div> : <Empty title="Nenhuma faixa cadastrada" copy="Cadastre um IP ou bloco CIDR formalmente autorizado." />)}
  </div><div className="drawer-foot"><button className="btn ghost" onClick={onClose}>Fechar</button>{mode === "Cadastrar faixa" && <button form="range-form" className="btn primary" disabled={busy}>{busy ? "Salvando…" : "Salvar faixa"}</button>}{mode === "Importar arquivo" && !preview && <button form="import-form" className="btn primary" disabled={busy}>{busy ? "Validando…" : "Validar arquivo"}</button>}{mode === "Importar arquivo" && preview && <><button className="btn ghost" onClick={() => setPreview(null)}>Nova prévia</button><button className="btn primary" disabled={busy || preview.valid === 0} onClick={() => void confirmImport()}>{busy ? "Importando…" : `Importar ${preview.valid} faixas`}</button></>}</div></aside></div>;
}

function ManualRun({ ranges, profiles, onClose, onCreated }: { ranges: AuthorizedRange[]; profiles: ScannerProfile[]; onClose: () => void; onCreated: (execution: ScanExecution) => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true); setError(null);
    try {
      const execution = await scannerRequest<ScanExecution>("executions", { method: "POST", body: JSON.stringify({ range_id: form.get("range_id"), profile_id: form.get("profile_id"), justification: form.get("justification") }) });
      onCreated(execution);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Falha ao iniciar execução."); }
    finally { setBusy(false); }
  }
  return <div className="scrim" onMouseDown={onClose}><aside className="drawer scan-drawer" onMouseDown={event => event.stopPropagation()}><div className="drawer-head"><div><span className="kicker">EXECUÇÃO CONTROLADA</span><h2>Executar scanner agora</h2></div><button onClick={onClose}>×</button></div><form onSubmit={submit}><div className="drawer-body"><ErrorNotice message={error} /><label className="field"><span>Faixa previamente autorizada</span><select name="range_id" required defaultValue=""><option value="" disabled>Selecione</option>{ranges.filter(item => item.enabled).map(item => <option key={item.id} value={item.id}>{item.name} · {item.cidr}</option>)}</select></label><label className="field"><span>Perfil do scanner</span><select name="profile_id" required defaultValue=""><option value="" disabled>Selecione</option>{profiles.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label className="field"><span>Justificativa da execução</span><textarea name="justification" rows={4} minLength={10} required /></label><div className="authorized-card"><Badge tone="ok">Somente escopo cadastrado</Badge><p>Não é possível digitar ou substituir o alvo nesta etapa.</p></div></div><div className="drawer-foot"><button type="button" className="btn ghost" onClick={onClose}>Cancelar</button><button className="btn primary" disabled={busy}>{busy ? "Enfileirando…" : "Iniciar execução"}</button></div></form></aside></div>;
}

export function ScannerOverview({ go }: { go: (page: ScannerPage) => void }) {
  const summary = usePolling<Summary>("summary", 10000);
  const ranges = usePolling<AuthorizedRange[]>("ranges", 15000);
  const profiles = usePolling<ScannerProfile[]>("profiles", 30000);
  const engines = usePolling<EngineStatus[]>("engines", 30000);
  const [rangeDrawer, setRangeDrawer] = useState(false);
  const [runDrawer, setRunDrawer] = useState(false);
  const scanEngines = engines.data?.filter(item => item.name !== "zabbix") ?? [];
  const activeEngines = scanEngines.filter(item => item.available).length;
  const engineTotal = scanEngines.length;
  return <><Header kicker="GESTÃO DE SUPERFÍCIE" title="Scanners" copy="Descoberta recorrente de ativos, serviços expostos e vulnerabilidades nas faixas autorizadas da prefeitura." actions={<><Badge tone={activeEngines === engineTotal && engineTotal > 0 ? "ok" : "warn"}>{engines.loading ? "Verificando motores" : `${activeEngines}/${engineTotal} motores disponíveis`}</Badge><button className="btn ghost" onClick={() => setRunDrawer(true)}>Executar agora</button><button className="btn primary" onClick={() => go("scan-schedules")}>+ Novo agendamento</button></>} />
    <ErrorNotice message={summary.error || engines.error} retry={() => void Promise.all([summary.refresh(), engines.refresh()])} />
    <div className="scan-scope"><span>✓</span><div><strong>Somente redes autorizadas</strong><p>Os agendamentos selecionam faixas previamente cadastradas. Toda alteração mantém responsável, justificativa e histórico.</p></div><button className="btn ghost" onClick={() => setRangeDrawer(true)}>Gerenciar faixas</button></div>
    <div className="metrics compact">{[["Cobertura autorizada", summary.data ? `${formatNumber(summary.data.authorized_ips)} IPs` : "—", summary.data ? `${summary.data.ranges_count} faixas` : "Carregando", "info"],["Ativos respondendo", summary.data ? formatNumber(summary.data.active_ips) : "—", summary.data ? `${summary.data.new_assets_30d} novos em 30 dias` : "Carregando", "ok"],["Serviços identificados", summary.data ? formatNumber(summary.data.services) : "—", summary.data ? `${summary.data.unlinked_assets} sem vínculo` : "Carregando", "warn"],["Vulnerabilidades abertas", summary.data ? formatNumber(summary.data.open_findings) : "—", summary.data ? `${summary.data.critical_findings} críticas` : "Carregando", "danger"]].map(item => <div className="metric" key={item[0]}><span><Dot tone={item[3] as Tone} />{item[0]}</span><strong>{item[1]}</strong><small>{item[2]}</small></div>)}</div>
    <div className="scan-dashboard"><section className="panel coverage"><div className="panel-head"><div><h2>Cobertura das faixas</h2><p>Última descoberta consolidada por segmento autorizado</p></div><button className="link" onClick={() => go("scan-assets")}>Ver inventário →</button></div>{summary.data?.coverage.length ? summary.data.coverage.map(item => <div className="coverage-row" key={item.id}><span><strong>{item.name}</strong><small className="mono">{item.cidr}</small></span><div><i style={{width:`${item.coverage_percent}%`}} /><b>{item.coverage_percent}%</b></div><ul><li>{item.active_assets} ativos</li><li>{item.services} serviços</li><li className={item.critical_findings ? "danger-text" : ""}>{item.critical_findings} críticos</li></ul></div>) : <Empty title="Nenhuma faixa com resultado" copy="Cadastre uma faixa autorizada e execute o primeiro scanner." />}</section>
      <section className="panel next-runs"><div className="panel-head"><div><h2>Próximas execuções</h2><p>Agenda operacional</p></div><button className="link" onClick={() => go("scan-schedules")}>Agenda →</button></div>{summary.data?.next_runs.length ? summary.data.next_runs.map(item => <button key={item.id} onClick={() => go("scan-runs")}><time>{formatDate(item.next_run_at)}</time><span><strong>{item.name}</strong><small>{item.profile_name} · <b className="mono">{item.cidr}</b></small></span><Badge tone="info">Agendado</Badge></button>) : <Empty title="Nenhuma execução agendada" copy="Crie uma rotina ou execute o scanner manualmente." />}</section></div>
    <section className="panel zabbix-strip"><div><span className="zabbix-mark">Z</span><span><strong>Integração Zabbix</strong><small>Reconciliação segura de hosts já existentes</small></span></div><div><span>Configuração<strong>{summary.data?.zabbix_configured ? "Ativa" : "Não configurada"}</strong></span><span>Pendências<strong>{summary.data?.zabbix_pending ?? 0}</strong></span><span>Motores de scan<strong>{activeEngines} ativos</strong></span></div><button className="btn ghost" onClick={() => go("scan-assets")}>Revisar inventário</button></section>
    {rangeDrawer && <RangeManager ranges={ranges.data ?? []} onClose={() => setRangeDrawer(false)} onChanged={ranges.refresh} />}
    {runDrawer && <ManualRun ranges={ranges.data ?? []} profiles={profiles.data ?? []} onClose={() => setRunDrawer(false)} onCreated={() => { setRunDrawer(false); go("scan-runs"); }} />}
  </>;
}

export function ScanSchedules({ go }: { go: (page: ScannerPage) => void }) {
  const schedules = usePolling<ScanSchedule[]>("schedules", 10000);
  const ranges = usePolling<AuthorizedRange[]>("ranges", 30000);
  const profiles = usePolling<ScannerProfile[]>("profiles", 30000);
  const [drawer, setDrawer] = useState(false);
  const [step, setStep] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState({ name: "", range_id: "", profile_id: "", recurrence: "weekly", time: "02:00", max_duration_minutes: "120", intensity: "low", sync_zabbix: false, justification: "" });
  const selectedRange = ranges.data?.find(item => item.id === draft.range_id);
  const selectedProfile = profiles.data?.find(item => item.id === draft.profile_id);
  const cron = draft.recurrence === "daily" ? `${draft.time.split(":")[1]} ${draft.time.split(":")[0]} * * *` : draft.recurrence === "monthly" ? `${draft.time.split(":")[1]} ${draft.time.split(":")[0]} 1 * *` : `${draft.time.split(":")[1]} ${draft.time.split(":")[0]} * * 0`;

  async function create() {
    setBusy(true); setError(null);
    try {
      await scannerRequest("schedules", { method: "POST", body: JSON.stringify({ name: draft.name, range_id: draft.range_id, profile_id: draft.profile_id, cron_expression: cron, timezone_name: "America/Sao_Paulo", max_duration_minutes: Number(draft.max_duration_minutes), intensity: draft.intensity, sync_zabbix: draft.sync_zabbix, justification: draft.justification }) });
      await schedules.refresh(); setDrawer(false);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Falha ao criar agendamento."); }
    finally { setBusy(false); }
  }

  async function toggle(item: ScanSchedule) {
    try { await scannerRequest(`schedules/${item.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !item.enabled }) }); await schedules.refresh(); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Falha ao atualizar agendamento."); }
  }

  return <><Header kicker="SCANNERS · CONTROLE RECORRENTE" title="Agendamentos" copy="Rotinas de descoberta e avaliação executadas em janelas controladas." actions={<button className="btn primary" onClick={() => { setStep(1); setError(null); setDrawer(true); }}>+ Novo agendamento</button>} /><ErrorNotice message={schedules.error || error} retry={schedules.refresh} />
    {schedules.data?.length ? <div className="table-wrap"><table><thead><tr>{["Agendamento","Nome","Faixa autorizada","Perfil","Recorrência","Próxima execução","Estado","Ação"].map(head => <th key={head}>{head}</th>)}</tr></thead><tbody>{schedules.data.map(item => <tr key={item.id} className="clickable" onClick={() => go("scan-runs")}><td className="mono">{shortId(item.id,"SCAN-AG")}</td><td>{item.name}</td><td className="mono">{item.cidr}</td><td>{item.profile_name}</td><td className="mono">{item.cron_expression}</td><td>{formatDate(item.next_run_at)}</td><td><Badge tone={item.enabled ? "ok" : "muted"}>{item.enabled ? "Ativo" : "Pausado"}</Badge></td><td><button className="btn ghost" onClick={event => { event.stopPropagation(); void toggle(item); }}>{item.enabled ? "Pausar" : "Ativar"}</button></td></tr>)}</tbody></table></div> : <Empty title="Nenhum scanner agendado" copy="Crie uma rotina usando somente faixas autorizadas." />}
    <div className="schedule-note"><Dot tone="info" /><span><strong>Controle de alteração</strong><small>Pausas, ativações e criações registram o responsável na auditoria.</small></span></div>
    {drawer && <div className="scrim" onMouseDown={() => setDrawer(false)}><aside className="drawer scan-drawer" onMouseDown={event => event.stopPropagation()}><div className="drawer-head"><div><span className="kicker">NOVO AGENDAMENTO · ETAPA {step} DE 3</span><h2>{step===1?"Escopo autorizado":step===2?"Perfil e recorrência":"Revisão e ativação"}</h2></div><button onClick={() => setDrawer(false)}>×</button></div><div className="stepper">{["Escopo","Configuração","Revisão"].map((item,index) => <span className={step>=index+1?"active":""} key={item}><b>{index+1}</b>{item}</span>)}</div><div className="drawer-body"><ErrorNotice message={error} />
      {step===1 && <><label className="field"><span>Nome do agendamento</span><input value={draft.name} onChange={event => setDraft({...draft,name:event.target.value})} /></label><label className="field"><span>Faixa previamente autorizada</span><select value={draft.range_id} onChange={event => setDraft({...draft,range_id:event.target.value})}><option value="">Selecione</option>{ranges.data?.filter(item=>item.enabled).map(item=><option key={item.id} value={item.id}>{item.name} · {item.cidr}</option>)}</select></label>{selectedRange && <div className="authorized-card"><Badge tone="ok">Autorizada</Badge><dl><div><dt>Responsável</dt><dd>{selectedRange.owner}</dd></div><div><dt>Ambiente</dt><dd>{selectedRange.environment}</dd></div><div><dt>Limite</dt><dd>{selectedRange.address_count} endereços</dd></div></dl><p>Não é possível digitar um IP ou CIDR fora do catálogo autorizado.</p></div>}</>}
      {step===2 && <><label className="field"><span>Perfil do scanner</span><select value={draft.profile_id} onChange={event=>setDraft({...draft,profile_id:event.target.value})}><option value="">Selecione</option>{profiles.data?.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label><div className="form-pair"><label className="field"><span>Recorrência</span><select value={draft.recurrence} onChange={event=>setDraft({...draft,recurrence:event.target.value})}><option value="daily">Diário</option><option value="weekly">Semanal</option><option value="monthly">Mensal</option></select></label><label className="field"><span>Horário</span><input type="time" value={draft.time} onChange={event=>setDraft({...draft,time:event.target.value})}/></label></div><div className="form-pair"><label className="field"><span>Janela máxima</span><select value={draft.max_duration_minutes} onChange={event=>setDraft({...draft,max_duration_minutes:event.target.value})}><option value="120">2 horas</option><option value="240">4 horas</option></select></label><label className="field"><span>Intensidade</span><select value={draft.intensity} onChange={event=>setDraft({...draft,intensity:event.target.value})}><option value="low">Baixa · recomendada</option><option value="moderate">Moderada</option></select></label></div><label className="field"><span>Integração após execução</span><select value={draft.sync_zabbix?"zabbix":"govsec"} onChange={event=>setDraft({...draft,sync_zabbix:event.target.value==="zabbix"})}><option value="govsec">Somente GovSec</option><option value="zabbix">Atualizar GovSec e reconciliar Zabbix</option></select></label></>}
      {step===3 && <div className="review-card"><Badge tone="info">Pronto para ativar</Badge><h3>{draft.name || "Agendamento sem nome"}</h3><dl><div><dt>Escopo</dt><dd>{selectedRange?.cidr} · {selectedRange?.environment}</dd></div><div><dt>Perfil</dt><dd>{selectedProfile?.name}</dd></div><div><dt>Expressão</dt><dd className="mono">{cron}</dd></div><div><dt>Intensidade</dt><dd>{draft.intensity === "low" ? "Baixa" : "Moderada"}</dd></div></dl><label className="field"><span>Justificativa</span><textarea rows={3} value={draft.justification} onChange={event=>setDraft({...draft,justification:event.target.value})}/></label></div>}
    </div><div className="drawer-foot"><button className="btn ghost" onClick={()=>step===1?setDrawer(false):setStep(step-1)}>{step===1?"Cancelar":"Voltar"}</button><button className="btn primary" disabled={busy || (step===1&&(!draft.name||!draft.range_id)) || (step===2&&!draft.profile_id) || (step===3&&draft.justification.length<10)} onClick={()=>step<3?setStep(step+1):void create()}>{busy?"Ativando…":step<3?"Continuar":"Ativar agendamento"}</button></div></aside></div>}
  </>;
}

export function ScanRuns({ go }: { go: (page: ScannerPage) => void }) {
  const executions = usePolling<ScanExecution[]>("executions", 5000);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = executions.data?.find(item => item.id === selectedId) ?? null;
  async function cancel() {
    if (!selected) return;
    await scannerRequest(`executions/${selected.id}/cancel`, { method: "POST", body: JSON.stringify({}) });
    await executions.refresh();
  }
  return <><Header kicker="SCANNERS · HISTÓRICO" title="Execuções" copy="Resultado de cada janela, cobertura obtida, mudanças e estado dos motores." actions={<button className="btn ghost" onClick={() => void executions.refresh()}>Atualizar</button>} /><ErrorNotice message={executions.error} retry={executions.refresh} />
    {executions.data?.length ? <div className="table-wrap"><table><thead><tr>{["Execução","Faixa","Perfil","Resultado","IPs ativos","Serviços","Críticas","Motores","Finalizada",""].map((head,index)=><th key={`${head}-${index}`}>{head}</th>)}</tr></thead><tbody>{executions.data.map(item=><tr key={item.id} className="clickable" onClick={()=>setSelectedId(item.id)}><td className="mono">{shortId(item.id,"SCAN-RUN")}</td><td><strong>{item.range_name}</strong><small className="mono">{item.cidr}</small></td><td>{item.profile_name}</td><td><Badge tone={statusTone(item.status)}>{statusLabel(item.status)}</Badge></td><td>{item.active_ips}</td><td>{item.services_discovered}</td><td>{item.critical_vulnerabilities}</td><td>{item.engine_runs.filter(run=>run.status==="completed").length}/{item.engine_runs.length || "—"}</td><td>{formatDate(item.finished_at || item.queued_at)}</td><td className="row-arrow">›</td></tr>)}</tbody></table></div> : <Empty title="Nenhuma execução registrada" copy="Execute um scanner manualmente ou crie um agendamento." />}
    {selected && <div className="scrim" onMouseDown={()=>setSelectedId(null)}><aside className="drawer run-drawer" onMouseDown={event=>event.stopPropagation()}><div className="drawer-head"><div><span className="kicker mono">{shortId(selected.id,"SCAN-RUN")}</span><h2>Resultado da execução</h2></div><button onClick={()=>setSelectedId(null)}>×</button></div><div className="drawer-body"><div className="run-result"><Badge tone={statusTone(selected.status)}>{statusLabel(selected.status)}</Badge><strong>{selected.range_name}</strong><small className="mono">{selected.cidr} · {formatDate(selected.started_at)}–{formatDate(selected.finished_at)}</small></div><div className="result-metrics">{[["IPs ativos",selected.active_ips],["Serviços",selected.services_discovered],["Vulnerabilidades",selected.vulnerabilities_discovered],["Críticas",selected.critical_vulnerabilities]].map(item=><div key={item[0]}><span>{item[0]}</span><strong>{item[1]}</strong></div>)}</div><h3>Motores</h3>{selected.engine_runs.length ? selected.engine_runs.map(run=><div className="change" key={run.engine}><b className={statusTone(run.status)}>{run.status==="completed"?"✓":"!"}</b><span><strong>{run.engine}</strong> · {run.result_count} resultados{run.error_message?` · ${run.error_message}`:""}</span></div>) : <p>Aguardando o worker iniciar os motores.</p>}{selected.error_summary && <ErrorNotice message={selected.error_summary} />}</div><div className="drawer-foot">{["queued","running"].includes(selected.status)&&<button className="btn ghost" onClick={()=>void cancel()}>Cancelar execução</button>}<button className="btn ghost" onClick={()=>setSelectedId(null)}>Fechar</button><button className="btn primary" onClick={()=>go("scan-assets")}>Ver IPs e serviços</button></div></aside></div>}
  </>;
}

export function ScanAssets() {
  const assets = usePolling<DiscoveredAsset[]>("assets", 10000);
  const findings = usePolling<VulnerabilityFinding[]>("findings", 15000);
  const [tab, setTab] = useState("IPs e serviços");
  const activeAssets = assets.data?.filter(item=>item.state==="active") ?? [];
  const serviceCount = activeAssets.reduce((total,item)=>total+item.services.length,0);
  const unlinked = activeAssets.filter(item=>!item.municipal_service).length;
  const inactive = assets.data?.filter(item=>item.state==="inactive").length ?? 0;
  return <><Header kicker="SCANNERS · INVENTÁRIO OBSERVADO" title="IPs e serviços" copy="Ativos descobertos, exposição observada e correspondência com o Zabbix." actions={<Badge tone="info">Dados reais do scanner</Badge>} /><ErrorNotice message={assets.error || findings.error} retry={()=>void Promise.all([assets.refresh(),findings.refresh()])} /><Tabs items={["IPs e serviços","Vulnerabilidades","Pendências Zabbix","Alterações"]} active={tab} setActive={setTab}/>
    {tab==="IPs e serviços" && <>{assets.data?.length ? <><div className="inventory-summary"><div><strong>{activeAssets.length}</strong><span>IPs ativos</span></div><div><strong>{serviceCount}</strong><span>serviços</span></div><div><strong>{unlinked}</strong><span>sem vínculo</span></div><div><strong>{inactive}</strong><span>ficaram inativos</span></div><p><Dot tone="warn"/> O scanner identifica o serviço técnico observado. O vínculo com um serviço municipal deve ser confirmado pelo responsável.</p></div><div className="table-wrap"><table><thead><tr>{["IP","Estado","Serviço municipal","Serviço observado","Portas","Vulnerabilidades","Zabbix","Verificado",""].map((head,index)=><th key={`${head}-${index}`}>{head}</th>)}</tr></thead><tbody>{assets.data.map(item=><tr key={item.id}><td className="mono">{item.ip_address}</td><td><Badge tone={item.state==="active"?"ok":"danger"}>{item.state==="active"?"Ativo":"Inativo"}</Badge></td><td>{item.municipal_service||"Sem vínculo"}</td><td>{item.services.map(service=>[service.product,service.version].filter(Boolean).join(" ")||service.service_name||"serviço").join(", ")||"—"}</td><td className="mono">{item.services.map(service=>`${service.port}/${service.protocol}`).join(", ")||"—"}</td><td>{item.open_findings}{item.highest_severity?` · ${item.highest_severity}`:""}</td><td>{item.zabbix_status}</td><td>{formatDate(item.last_seen_at)}</td><td className="row-arrow">›</td></tr>)}</tbody></table></div></> : <Empty title="Nenhum IP identificado" copy="O inventário será preenchido após a primeira execução concluída." />}</>}
    {tab==="Vulnerabilidades" && <>{findings.data?.length ? <div className="table-wrap"><table><thead><tr>{["IP","Serviço","Identificador","Nome","Severidade","Primeiro visto","Último visto","Estado"].map(head=><th key={head}>{head}</th>)}</tr></thead><tbody>{findings.data.map(item=><tr key={item.id}><td className="mono">{item.ip_address}</td><td>{item.service||"—"}</td><td className="mono">{item.template_id}</td><td>{item.name}</td><td><Badge tone={statusTone(item.severity)}>{item.severity}</Badge></td><td>{formatDate(item.first_seen_at)}</td><td>{formatDate(item.last_seen_at)}</td><td>{item.status}</td></tr>)}</tbody></table></div> : <Empty title="Nenhuma vulnerabilidade identificada" copy="Somente achados confirmados pelos motores reais aparecem aqui." />}</>}
    {tab==="Pendências Zabbix" && <>{assets.data?.some(item=>item.zabbix_status==="pending") ? <div className="changes-feed">{assets.data.filter(item=>item.zabbix_status==="pending").map(item=><article key={item.id}><Dot tone="warn"/><span><strong className="mono">{item.ip_address}</strong><p>Host correspondente não encontrado no Zabbix.</p></span></article>)}</div> : <Empty title="Nenhuma pendência Zabbix" copy="A integração não cria hosts automaticamente; apenas reconcilia registros existentes." />}</>}
    {tab==="Alterações" && <Empty title="Histórico derivado das execuções" copy="Novos ativos, serviços e mudanças ficam preservados pela data da primeira e última observação." />}
  </>;
}
