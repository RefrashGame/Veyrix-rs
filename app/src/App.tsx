import { useCallback, useEffect, useRef, useState, type ComponentType, type ReactNode } from "react"
import { listen } from "@tauri-apps/api/event"
import {
  PictureInPicture2,
  Power,
  ScrollText,
  Send,
  ServerCog,
  Settings as SettingsIcon,
  Stethoscope,
  Waypoints,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { MiniView } from "@/components/mini-view"
import { ServiceMap, type MapSite, type Verdict } from "@/components/service-map"
import { IconButton, WindowButtons } from "@/components/window-controls"
import { isTauri, trackedInvoke as invoke } from "@/lib/tauri"
import logo from "../src-tauri/icons/128x128.png"

type Settings = {
  auto: boolean
  quic: "fake" | "drop" | "pass"
  doh: string
  discordVoice: boolean
  telegram: boolean
  tgPort: number
  tgSecret: string
  tgCloudflare: boolean
  mini: boolean
  ipBlock: "off" | "cloudflare" | "proxy" | "warp"
  ipProxy: string
}

type Stats = {
  changed: number
  passed: number
  dropped: number
  sendErrors: number
  dohOk: number
  dohFallback: number
  ipBlocked: number
  ipRerouted: number
}

type Status = { running: boolean; stats: Stats; dohServer: string | null; uptimeSecs: number; sites: MapSite[] }

type LogKind = "site" | "works" | "switched" | "warning" | "info" | "error" | "reroute"
type LogItem = { id: number; time: string; kind: LogKind; text: string }

const LOG_LIMIT = 500

const KIND_LABEL: Record<LogKind, string> = {
  site: "сайт",
  works: "работает",
  switched: "смена приёма",
  warning: "внимание",
  info: "движок",
  error: "ошибка",
  reroute: "обход по IP",
}

const KIND_VARIANT: Record<LogKind, "default" | "secondary" | "destructive" | "outline"> = {
  site: "outline",
  works: "default",
  switched: "secondary",
  warning: "destructive",
  info: "outline",
  error: "destructive",
  reroute: "secondary",
}

type Page = "overview" | "log" | "telegram" | "diag" | "dns" | "settings"

const PAGES: { id: Page; title: string; icon: ComponentType<{ className?: string }>; group?: string }[] = [
  { id: "overview", title: "Обзор", icon: Waypoints },
  { id: "log", title: "Журнал", icon: ScrollText },
  { id: "telegram", title: "Telegram", icon: Send },
  { id: "diag", title: "Диагностика", icon: Stethoscope },
  { id: "dns", title: "DNS Windows", icon: ServerCog, group: "Система" },
  { id: "settings", title: "Настройки", icon: SettingsIcon },
]

function now() {
  return new Date().toLocaleTimeString("ru-RU")
}

function uptime(secs: number) {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  return h > 0 ? `${h} ч ${m} мин` : m > 0 ? `${m} мин` : "меньше минуты"
}

export function App() {
  const [page, setPage] = useState<Page>("overview")
  const [settings, setSettings] = useState<Settings | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [tg, setTg] = useState<TgStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [log, setLog] = useState<LogItem[]>([])
  const [verdicts, setVerdicts] = useState<Record<string, Verdict>>({})
  const nextId = useRef(0)

  const addLog = useCallback((kind: LogKind, text: string) => {
    setLog((items) => [{ id: nextId.current++, time: now(), kind, text }, ...items].slice(0, LOG_LIMIT))
  }, [])

  useEffect(() => {
    if (!isTauri()) return
    invoke<Settings>("load_settings").then(setSettings, (e) => setError(String(e)))
    invoke<Status>("engine_status").then(setStatus, () => {})
    const unlisten = listen<{ kind: LogKind; text: string; site?: string }>("vx-event", (e) => {
      const { kind, text, site } = e.payload
      addLog(kind, text)
      // Итог автоподбора по сайту — для отметки на карте.
      if (site && (kind === "works" || kind === "switched")) setVerdicts((v) => ({ ...v, [site]: kind }))
    })
    // Старт/стоп из трея или автозапуска — окно узнаёт новое состояние.
    const unlistenStatus = listen<Status>("vx-status", (e) => setStatus(e.payload))
    return () => {
      unlisten.then((stop) => stop())
      unlistenStatus.then((stop) => stop())
    }
  }, [addLog])

  // Пока обход работает, счётчики обновляются раз в секунду.
  useEffect(() => {
    if (!status?.running) return
    const timer = setInterval(() => {
      invoke<Status>("engine_status").then(setStatus, () => {})
    }, 1000)
    return () => clearInterval(timer)
  }, [status?.running])

  // Секундный тик для карты: по нему она отсчитывает, давно ли рос трафик.
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const timer = setInterval(() => setTick((t) => t + 1), 1000)
    return () => clearInterval(timer)
  }, [])

  // Состояние Telegram-прокси для карты.
  useEffect(() => {
    if (!isTauri()) return
    const poll = () => invoke<TgStatus>("tg_status").then(setTg, () => {})
    poll()
    const timer = setInterval(poll, 2000)
    return () => clearInterval(timer)
  }, [])

  async function toggle() {
    if (!settings) return
    setBusy(true)
    setError(null)
    try {
      if (status?.running) {
        const s = await invoke<Status>("engine_stop")
        setStatus(s)
        addLog("info", `Обход остановлен: изменено соединений ${s.stats.changed}`)
      } else {
        const s = await invoke<Status>("engine_start", { settings })
        setStatus(s)
        setVerdicts({})
        addLog("info", "Обход запущен")
      }
    } catch (e) {
      setError(String(e))
      addLog("error", String(e))
    } finally {
      setBusy(false)
    }
  }

  async function update(patch: Partial<Settings>) {
    if (!settings) return
    const next = { ...settings, ...patch }
    setSettings(next)
    try {
      await invoke("save_settings", { settings: next })
    } catch (e) {
      setError(String(e))
    }
  }

  if (!isTauri()) {
    return <p className="p-6 text-sm">Откройте Veyrix как приложение: в браузере обход недоступен.</p>
  }

  const running = status?.running ?? false
  const stats = status?.stats
  const current = PAGES.find((p) => p.id === page)!

  // Мини-режим: выбор сохраняется в настройках, размер окна меняет Rust (вручную окно не растягивается).
  async function setMini(mini: boolean) {
    await update({ mini })
    invoke("window_mode", { mini }).catch((e) => setError(String(e)))
  }

  if (settings?.mini) {
    return (
      <MiniView
        running={running}
        busy={busy}
        uptime={uptime(status?.uptimeSecs ?? 0)}
        settings={settings}
        dohServer={status?.dohServer ?? null}
        stats={stats}
        sites={status?.sites ?? []}
        verdicts={verdicts}
        tg={tg}
        error={error}
        onToggle={toggle}
        onExpand={() => setMini(false)}
      />
    )
  }

  return (
    <div className="flex h-svh">
      <Sidebar page={page} setPage={setPage} />

      <div className="flex min-w-0 flex-1 flex-col py-5 pr-7 pl-2">
        {/* Шапка — она же заголовок окна: за пустое место окно перетаскивается. */}
        <header data-tauri-drag-region className="mb-4 flex items-center gap-3">
          <h1 data-tauri-drag-region className="text-[21px] font-extrabold tracking-tight">
            {current.title}
          </h1>
          <div data-tauri-drag-region className="h-10 flex-1" />
          <div className="flex h-10 items-center gap-2.5 rounded-full border bg-[#141615] px-4 text-sm font-semibold">
            <span
              className={`size-2 rounded-full ${running ? "bg-primary shadow-[0_0_10px_var(--primary)]" : "bg-[#5d615e]"}`}
            />
            {running ? `Обход включён · ${uptime(status?.uptimeSecs ?? 0)}` : "Обход выключен"}
          </div>
          <IconButton title="Мини-режим" icon={PictureInPicture2} onClick={() => setMini(true)} />
          <Button
            className="h-10 rounded-full px-5 font-bold"
            variant={running ? "secondary" : "default"}
            disabled={busy || !settings}
            onClick={toggle}
          >
            <Power />
            {running ? "Остановить" : "Запустить обход"}
          </Button>
          <div className="ml-1 h-6 w-px bg-border" />
          <WindowButtons />
        </header>

        {error && (
          <p className="mb-3 rounded-2xl border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{error}</p>
        )}

        <div data-ui-scroll-container className="flex min-h-0 flex-1 flex-col">
          {page === "overview" && (
            <div className="flex min-h-full flex-col gap-3">
              <div className="grid grid-cols-4 gap-3">
                <Stat label="Соединений с приёмом" value={stats?.changed} />
                <Stat label="Пропущено без изменений" value={stats?.passed} />
                <Stat label="QUIC отброшено" value={stats?.dropped} />
                <Stat label="DNS через DoH" value={stats?.dohOk} hint={stats?.dohFallback ? `обычным путём: ${stats.dohFallback}` : undefined} />
              </div>
              {(stats?.ipBlocked ?? 0) > 0 && (
                <p className="text-sm text-muted-foreground">
                  Блокировка по IP: обходится адресов — {stats?.ipBlocked}, соединений через обход — {stats?.ipRerouted}.
                  Подробности в журнале.
                </p>
              )}
              {(stats?.sendErrors ?? 0) > 0 && (
                <p className="text-sm text-warning">Не отправлено пакетов: {stats?.sendErrors} — подробности в журнале.</p>
              )}
              {settings && (
                <ServiceMap
                  tick={tick}
                  running={running}
                  auto={settings.auto}
                  quic={settings.quic}
                  doh={settings.doh}
                  dohServer={status?.dohServer ?? null}
                  stats={stats}
                  sites={status?.sites ?? []}
                  verdicts={verdicts}
                  tg={tg}
                />
              )}
              <p className="text-xs text-muted-foreground">
                Крестик сворачивает окно в значок у часов — обход продолжает работать. Выйти — через меню значка.
              </p>
            </div>
          )}

          {page === "log" && (
            <Panel>
              <div className="mb-3 flex items-center justify-between">
                <p className="text-sm text-muted-foreground">Последние {LOG_LIMIT} событий, новые сверху.</p>
                <Button variant="outline" size="sm" onClick={() => setLog([])} disabled={log.length === 0}>
                  Очистить
                </Button>
              </div>
              <ul className="flex flex-col gap-1.5 font-mono text-xs">
                {log.length === 0 && <li className="text-muted-foreground">Пока пусто — запустите обход и откройте сайт.</li>}
                {log.map((item) => (
                  <li key={item.id} className="flex items-baseline gap-2">
                    <span className="text-muted-foreground tabular-nums">{item.time}</span>
                    <Badge variant={KIND_VARIANT[item.kind]} className="shrink-0">
                      {KIND_LABEL[item.kind]}
                    </Badge>
                    <span className="ui-selectable break-all">{item.text}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {page === "telegram" && settings && (
            <Panel narrow>
              <Telegram settings={settings} update={update} status={tg} setStatus={setTg} />
            </Panel>
          )}

          {page === "diag" && (
            <Panel narrow>
              <Diagnostics />
            </Panel>
          )}

          {page === "dns" && (
            <Panel narrow>
              <SystemDns />
            </Panel>
          )}

          {page === "settings" && (
            <Panel narrow>
              {!settings ? (
                <p className="text-sm text-muted-foreground">Загрузка…</p>
              ) : (
                <div className="flex flex-col gap-5 text-sm">
                  {running && <p className="text-muted-foreground">Изменения применятся после перезапуска обхода.</p>}
                  <Autostart />
                  <Check
                    checked={settings.auto}
                    onChange={(auto) => update({ auto })}
                    title="Автоподбор приёма"
                    hint="Для каждого сайта свой приём; если сайт перестал открываться — программа сама пробует следующий."
                  />
                  <Choice
                    title="QUIC (HTTP/3)"
                    value={settings.quic}
                    onChange={(quic) => update({ quic: quic as Settings["quic"] })}
                    options={[
                      ["fake", "Фейк перед QUIC"],
                      ["drop", "Выключить QUIC — браузер перейдёт на обычный HTTPS"],
                      ["pass", "Не трогать"],
                    ]}
                  />
                  <Choice
                    title="DNS"
                    value={settings.doh}
                    onChange={(doh) => update({ doh })}
                    options={[
                      ["off", "Обычный DNS"],
                      ["cloudflare", "DNS-over-HTTPS: Cloudflare"],
                      ["google", "DNS-over-HTTPS: Google"],
                      ["quad9", "DNS-over-HTTPS: Quad9"],
                    ]}
                  />
                  <Check
                    checked={settings.discordVoice}
                    onChange={(discordVoice) => update({ discordVoice })}
                    title="Обход для голоса Discord"
                    hint="Только если провайдер режет голосовые звонки: у части провайдеров это, наоборот, ломает голос."
                  />
                  <IpBlock settings={settings} update={update} />
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  )
}

function Sidebar({ page, setPage }: { page: Page; setPage: (p: Page) => void }) {
  return (
    <aside className="m-3 flex w-[230px] shrink-0 flex-col gap-1 rounded-[22px] border border-sidebar-border bg-sidebar px-3 py-4">
      <div data-tauri-drag-region className="flex items-center gap-3 px-2 pb-6">
        <img src={logo} alt="" className="size-9 rounded-xl" />
        <b className="text-xl font-extrabold tracking-tight">Veyrix</b>
      </div>
      {PAGES.map((p) => (
        <div key={p.id} className="contents">
          {p.group && <div className="px-3 pt-4 pb-1.5 text-xs font-semibold text-muted-foreground">{p.group}</div>}
          <button
            type="button"
            onClick={() => setPage(p.id)}
            className={`flex items-center gap-3 rounded-xl px-3 py-2.5 text-left text-sm font-semibold transition-colors ${
              page === p.id
                ? "bg-sidebar-accent text-sidebar-accent-foreground [&_svg]:text-primary"
                : "text-sidebar-foreground hover:bg-[#161817]"
            }`}
          >
            <p.icon className="size-[18px]" />
            {p.title}
          </button>
        </div>
      ))}
    </aside>
  )
}

function Panel({ children, narrow }: { children: ReactNode; narrow?: boolean }) {
  return (
    <section className={`rounded-[22px] border bg-[#121413]/90 p-6 ${narrow ? "max-w-3xl" : ""}`}>{children}</section>
  )
}

const IP_BLOCK_HINT: Record<Settings["ipBlock"], string> = {
  off: "Если до адреса сайта не доходят даже пакеты подключения, программа только сообщит об этом в журнале.",
  cloudflare:
    "Только для сайтов за Cloudflare (Discord и многие другие): заблокированный адрес заменяется другим адресом Cloudflare, " +
    "который отвечает. Работает на этом компьютере, без посредников.",
  proxy:
    "Соединения с заблокированными адресами идут через ваш SOCKS5-прокси (любые сайты). Прокси видит, к какому адресу " +
    "вы подключаетесь; содержимое защищено HTTPS.",
  warp:
    "Соединения с заблокированными адресами идут через Cloudflare WARP (любые сайты). WARP нужно установить самим " +
    "(1.1.1.1 от Cloudflare), включить режим прокси — warp-cli mode proxy — и подключиться: warp-cli connect.",
}

/// Обход блокировки по IP: режим и адрес своего прокси.
function IpBlock(props: { settings: Settings; update: (patch: Partial<Settings>) => void }) {
  const { settings, update } = props
  const [proxy, setProxy] = useState(settings.ipProxy)

  function choose(mode: string) {
    const ipBlock = mode as Settings["ipBlock"]
    if (ipBlock === "proxy" || ipBlock === "warp") {
      const ok = window.confirm(
        "Для этого режима Veyrix при запуске обхода добавит правило брандмауэра Windows " +
          "«Veyrix-rs: обход блокировки по IP» — оно разрешает программе принимать перенаправленные соединения. " +
          "При остановке обхода правило удаляется.\n\nПродолжить?",
      )
      if (!ok) return
    }
    update({ ipBlock })
  }

  return (
    <div className="flex flex-col gap-2">
      <Choice
        title="Если сайт заблокирован по IP-адресу"
        value={settings.ipBlock}
        onChange={choose}
        options={[
          ["off", "Ничего не делать"],
          ["cloudflare", "Другой адрес Cloudflare — локально"],
          ["proxy", "Через свой SOCKS5-прокси"],
          ["warp", "Через Cloudflare WARP"],
        ]}
      />
      <p className="text-muted-foreground">{IP_BLOCK_HINT[settings.ipBlock]}</p>
      {settings.ipBlock === "proxy" && (
        <label className="flex flex-col gap-1">
          <span className="font-medium">Адрес прокси</span>
          <input
            className="rounded-xl border bg-background px-3 py-2"
            placeholder="127.0.0.1:1080 или socks5://логин:пароль@10.0.0.2:1080"
            value={proxy}
            onChange={(e) => setProxy(e.target.value)}
            onBlur={() => proxy !== settings.ipProxy && update({ ipProxy: proxy.trim() })}
          />
        </label>
      )}
    </div>
  )
}

type TgStatus = {
  running: boolean
  port: number
  link: string
  active: number
  viaWs: number
  viaCloudflare: number
  viaTcp: number
  up: number
  down: number
  badHandshakes: number
}

function mb(bytes: number) {
  return `${(bytes / 1024 / 1024).toFixed(1)} МБ`
}

/// Telegram-прокси на 127.0.0.1: старт/стоп, ссылка для Telegram Desktop, маршруты.
/// Состояние опрашивает App (оно же нужно карте на «Обзоре»).
function Telegram(props: {
  settings: Settings
  update: (patch: Partial<Settings>) => void
  status: TgStatus | null
  setStatus: (s: TgStatus) => void
}) {
  const { status, setStatus } = props
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function run(command: "tg_start" | "tg_stop") {
    setBusy(true)
    setError(null)
    try {
      setStatus(await invoke<TgStatus>(command))
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function connect() {
    try {
      await invoke("tg_open_link")
    } catch (e) {
      setError(String(e))
    }
  }

  const running = status?.running ?? false
  return (
    <div className="flex flex-col gap-4 text-sm">
      <p className="text-muted-foreground">
        Локальный прокси для Telegram Desktop: если провайдер блокирует Telegram, трафик идёт через веб-вход Telegram,
        резерв через Cloudflare или напрямую — что ответит первым. Обход DPI для этого не нужен.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={running ? "secondary" : "default"} disabled={busy} onClick={() => run(running ? "tg_stop" : "tg_start")}>
          {running ? "Остановить прокси" : "Запустить прокси"}
        </Button>
        <Button variant="outline" disabled={!running} onClick={connect}>
          Подключить Telegram
        </Button>
        <Badge variant={running ? "default" : "outline"}>{running ? `127.0.0.1:${status?.port}` : "Прокси остановлен"}</Badge>
      </div>
      {error && <p className="text-destructive">{error}</p>}
      {running && status && (
        <>
          <p className="text-muted-foreground">
            «Подключить Telegram» откроет ссылку — Telegram Desktop сам предложит включить прокси. Ссылка:{" "}
            <span className="font-mono break-all select-all">{status.link}</span>
          </p>
          <div className="grid grid-cols-4 gap-3">
            <Stat label="Соединений сейчас" value={status.active} />
            <Stat label="Через веб-вход" value={status.viaWs} />
            <Stat label="Через Cloudflare" value={status.viaCloudflare} />
            <Stat label="Напрямую" value={status.viaTcp} />
          </div>
          <p className="text-muted-foreground">
            Передано: {mb(status.up)} ↑ · {mb(status.down)} ↓
            {status.badHandshakes > 0 && " · были подключения с неверным ключом — подключите Telegram заново"}
          </p>
        </>
      )}
      <Check
        checked={props.settings.tgCloudflare}
        onChange={(tgCloudflare) => props.update({ tgCloudflare })}
        title="Резерв через Cloudflare (серверы Flowseal)"
        hint="Если серверы Telegram заблокированы по IP. Посредник видит факт подключения, но не переписку: трафик зашифрован Telegram."
      />
      <Check
        checked={props.settings.telegram}
        onChange={(telegram) => props.update({ telegram })}
        title="Запускать прокси вместе с Veyrix"
        hint="Изменения порта и резерва применятся после перезапуска прокси."
      />
    </div>
  )
}

type DiagCheck = { name: string; level: "ok" | "warning" | "failed"; detail: string; hint: string | null }

const LEVEL: Record<DiagCheck["level"], { label: string; variant: "default" | "secondary" | "destructive" }> = {
  ok: { label: "в порядке", variant: "default" },
  warning: { label: "внимание", variant: "secondary" },
  failed: { label: "ошибка", variant: "destructive" },
}

/// Диагностика: только чтение системы и один DoH-запрос.
function Diagnostics() {
  const [checks, setChecks] = useState<DiagCheck[] | null>(null)
  const [busy, setBusy] = useState(false)

  async function run() {
    setBusy(true)
    try {
      setChecks(await invoke<DiagCheck[]>("diagnostics"))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-3 text-sm">
      <div className="flex items-center gap-3">
        <Button onClick={run} disabled={busy}>
          {busy ? "Проверяю…" : "Проверить"}
        </Button>
        <span className="text-muted-foreground">Права, WinDivert, служба BFE, другие перехватчики, VPN, прокси, DoH.</span>
      </div>
      <ul className="flex flex-col gap-2">
        {checks?.map((c) => (
          <li key={c.name} className="rounded-2xl bg-card p-3">
            <div className="flex items-center gap-2">
              <Badge variant={LEVEL[c.level].variant}>{LEVEL[c.level].label}</Badge>
              <span className="font-medium">{c.name}</span>
              <span className="text-muted-foreground">{c.detail}</span>
            </div>
            {c.level !== "ok" && c.hint && <p className="mt-1 text-muted-foreground">{c.hint}</p>}
          </li>
        ))}
      </ul>
    </div>
  )
}

/// Автозапуск — задача Планировщика Windows (создаётся только этим переключателем).
function Autostart() {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    invoke<boolean>("autostart_status").then(setEnabled, () => setEnabled(false))
  }, [])

  async function set(value: boolean) {
    setError(null)
    try {
      setEnabled(await invoke<boolean>("autostart_set", { enabled: value }))
    } catch (e) {
      setError(String(e))
    }
  }

  return (
    <div className="flex flex-col gap-1">
      <Check
        checked={enabled ?? false}
        onChange={set}
        title="Запускать вместе с Windows"
        hint="При входе в Windows Veyrix запустится в трее и сразу включит обход с этими настройками (задача «Veyrix-rs» в Планировщике)."
      />
      {error && <p className="text-destructive">{error}</p>}
    </div>
  )
}

type SysDns = { adapters: { name: string; dns: string }[]; replaced: boolean; servers: string[] }

/// DNS Windows: меняет системную настройку адаптеров, поэтому — только по кнопке и с подтверждением.
function SystemDns() {
  const [state, setState] = useState<SysDns | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    invoke<SysDns>("sysdns_status").then(setState, (e) => setMessage(String(e)))
  }, [])

  async function run(command: "sysdns_apply" | "sysdns_restore", done: string) {
    setBusy(true)
    setMessage(null)
    try {
      setState(await invoke<SysDns>(command))
      setMessage(done)
    } catch (e) {
      setMessage(String(e))
      invoke<SysDns>("sysdns_status").then(setState, () => {})
    } finally {
      setBusy(false)
    }
  }

  function apply() {
    const servers = state?.servers.join(" и ") ?? "Яндекс"
    const ok = window.confirm(
      `Заменить DNS Windows на ${servers} (Яндекс) на включённых адаптерах Ethernet и Wi-Fi?\n\n` +
        "Это системная настройка: она действует и без Veyrix. Исходные настройки сохранятся — " +
        "кнопка «Вернуть исходный DNS» восстановит их. Кэш DNS будет очищен.",
    )
    if (ok) run("sysdns_apply", "DNS заменён, кэш очищен.")
  }

  return (
    <section className="flex flex-col gap-3 text-sm">
      <p className="text-muted-foreground">
        Системный DNS адаптеров Ethernet и Wi-Fi. Замена действует и без Veyrix; исходные настройки сохраняются, их
        можно вернуть.
      </p>
      <ul className="flex flex-col gap-2">
        {state?.adapters.length === 0 && <li className="text-muted-foreground">Нет включённых адаптеров Ethernet или Wi-Fi.</li>}
        {state?.adapters.map((a) => (
          <li key={a.name} className="flex justify-between gap-4 rounded-2xl bg-card px-4 py-3">
            <span className="font-medium">{a.name}</span>
            <span className="text-muted-foreground">{a.dns ? a.dns.replaceAll(",", ", ") : "автоматически (DHCP)"}</span>
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy || !state} onClick={apply}>
          Заменить на Яндекс ({state?.servers.join(", ") ?? "…"})
        </Button>
        <Button
          variant="outline"
          disabled={busy || !state?.replaced}
          onClick={() => run("sysdns_restore", "Исходный DNS возвращён, кэш очищен.")}
        >
          Вернуть исходный DNS
        </Button>
      </div>
      {state?.replaced && <p className="text-muted-foreground">DNS заменён программой — исходный можно вернуть.</p>}
      {message && <p>{message}</p>}
    </section>
  )
}

function Stat({ label, value, hint }: { label: string; value: number | undefined; hint?: string }) {
  return (
    <div className="rounded-2xl border bg-[#141615]/85 px-4 py-3">
      <div className="text-xs font-semibold text-muted-foreground">{label}</div>
      <div className="mt-1 text-[22px] font-extrabold tabular-nums">{(value ?? 0).toLocaleString("ru-RU")}</div>
      {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
    </div>
  )
}

function Check(props: { checked: boolean; onChange: (v: boolean) => void; title: string; hint: string }) {
  return (
    <label className="flex cursor-pointer items-start gap-3">
      <input
        type="checkbox"
        className="mt-1 size-4 accent-primary"
        checked={props.checked}
        onChange={(e) => props.onChange(e.target.checked)}
      />
      <span>
        <span className="font-medium">{props.title}</span>
        <span className="block text-muted-foreground">{props.hint}</span>
      </span>
    </label>
  )
}

function Choice(props: { title: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-medium">{props.title}</span>
      <select
        className="rounded-xl border bg-background px-3 py-2"
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
      >
        {props.options.map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </label>
  )
}

export default App
