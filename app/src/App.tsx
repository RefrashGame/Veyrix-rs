import { useCallback, useEffect, useRef, useState } from "react"
import { listen } from "@tauri-apps/api/event"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { isTauri, trackedInvoke as invoke } from "@/lib/tauri"

type Settings = {
  auto: boolean
  quic: "fake" | "drop" | "pass"
  doh: string
  discordVoice: boolean
  telegram: boolean
  tgPort: number
  tgSecret: string
  tgCloudflare: boolean
}

type Stats = {
  changed: number
  passed: number
  dropped: number
  sendErrors: number
  dohOk: number
  dohFallback: number
}

type Status = { running: boolean; stats: Stats; dohServer: string | null }

type LogKind = "site" | "works" | "switched" | "warning" | "info" | "error"
type LogItem = { id: number; time: string; kind: LogKind; text: string }

const LOG_LIMIT = 500

const KIND_LABEL: Record<LogKind, string> = {
  site: "сайт",
  works: "работает",
  switched: "смена приёма",
  warning: "внимание",
  info: "движок",
  error: "ошибка",
}

const KIND_VARIANT: Record<LogKind, "default" | "secondary" | "destructive" | "outline"> = {
  site: "outline",
  works: "default",
  switched: "secondary",
  warning: "destructive",
  info: "outline",
  error: "destructive",
}

function now() {
  return new Date().toLocaleTimeString("ru-RU")
}

export function App() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [status, setStatus] = useState<Status | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [log, setLog] = useState<LogItem[]>([])
  const nextId = useRef(0)

  const addLog = useCallback((kind: LogKind, text: string) => {
    setLog((items) => [{ id: nextId.current++, time: now(), kind, text }, ...items].slice(0, LOG_LIMIT))
  }, [])

  useEffect(() => {
    if (!isTauri()) return
    invoke<Settings>("load_settings").then(setSettings, (e) => setError(String(e)))
    invoke<Status>("engine_status").then(setStatus, () => {})
    const unlisten = listen<{ kind: LogKind; text: string }>("vx-event", (e) => addLog(e.payload.kind, e.payload.text))
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

  return (
    <div className="flex min-h-svh flex-col gap-4 p-6">
      <header className="flex items-center justify-between">
        <h1 className="text-xl font-semibold tracking-tight">Veyrix</h1>
        <Badge variant={running ? "default" : "outline"}>{running ? "Обход работает" : "Обход остановлен"}</Badge>
      </header>

      <Tabs defaultValue="overview" className="flex-1">
        <TabsList>
          <TabsTrigger value="overview">Обзор</TabsTrigger>
          <TabsTrigger value="log">Журнал</TabsTrigger>
          <TabsTrigger value="telegram">Telegram</TabsTrigger>
          <TabsTrigger value="diag">Диагностика</TabsTrigger>
          <TabsTrigger value="settings">Настройки</TabsTrigger>
        </TabsList>

        <TabsContent value="telegram" className="pt-4">
          {settings && <Telegram settings={settings} update={update} />}
        </TabsContent>

        <TabsContent value="diag" className="pt-4">
          <Diagnostics />
        </TabsContent>

        <TabsContent value="overview" className="flex flex-col gap-4 pt-4">
          <div className="flex items-center gap-4">
            <Button size="lg" variant={running ? "destructive" : "default"} disabled={busy || !settings} onClick={toggle}>
              {running ? "Остановить" : "Запустить обход"}
            </Button>
            <p className="text-sm text-muted-foreground">
              {settings &&
                [
                  settings.auto ? "автоподбор приёмов" : "приём по умолчанию",
                  { fake: "QUIC: фейк", drop: "QUIC: выключен", pass: "QUIC: без изменений" }[settings.quic],
                  settings.doh === "off" ? "обычный DNS" : `DNS через DoH (${status?.dohServer ?? settings.doh})`,
                ].join(" · ")}
            </p>
          </div>
          {error && <p className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Stat label="Соединений с приёмом" value={stats?.changed} />
            <Stat label="Пропущено без изменений" value={stats?.passed} />
            <Stat label="QUIC отброшено" value={stats?.dropped} />
            <Stat label="DNS через DoH" value={stats?.dohOk} />
            <Stat label="DNS обычным путём" value={stats?.dohFallback} />
            <Stat label="Ошибок отправки" value={stats?.sendErrors} />
          </div>
          <p className="text-xs text-muted-foreground">
            Крестик сворачивает окно в значок у часов — обход продолжает работать. Выйти — через меню значка.
          </p>
        </TabsContent>

        <TabsContent value="log" className="flex flex-col gap-3 pt-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">Последние {LOG_LIMIT} событий, новые сверху.</p>
            <Button variant="outline" size="sm" onClick={() => setLog([])} disabled={log.length === 0}>
              Очистить
            </Button>
          </div>
          <ul className="flex flex-col gap-1 font-mono text-xs">
            {log.length === 0 && <li className="text-muted-foreground">Пока пусто — запустите обход и откройте сайт.</li>}
            {log.map((item) => (
              <li key={item.id} className="flex items-baseline gap-2">
                <span className="text-muted-foreground tabular-nums">{item.time}</span>
                <Badge variant={KIND_VARIANT[item.kind]} className="shrink-0">
                  {KIND_LABEL[item.kind]}
                </Badge>
                <span className="break-all">{item.text}</span>
              </li>
            ))}
          </ul>
        </TabsContent>

        <TabsContent value="settings" className="flex max-w-xl flex-col gap-5 pt-4 text-sm">
          {!settings ? (
            <p className="text-muted-foreground">Загрузка…</p>
          ) : (
            <>
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
              <SystemDns />
            </>
          )}
        </TabsContent>
      </Tabs>
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
function Telegram(props: { settings: Settings; update: (patch: Partial<Settings>) => void }) {
  const [status, setStatus] = useState<TgStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    invoke<TgStatus>("tg_status").then(setStatus, () => {})
    const timer = setInterval(() => invoke<TgStatus>("tg_status").then(setStatus, () => {}), 2000)
    return () => clearInterval(timer)
  }, [])

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
    <div className="flex max-w-2xl flex-col gap-4 text-sm">
      <p className="text-muted-foreground">
        Локальный прокси для Telegram Desktop: если провайдер блокирует Telegram, трафик идёт через веб-вход Telegram,
        резерв через Cloudflare или напрямую — что ответит первым. Обход DPI для этого не нужен.
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={running ? "destructive" : "default"} disabled={busy} onClick={() => run(running ? "tg_stop" : "tg_start")}>
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
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
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
    <div className="flex max-w-2xl flex-col gap-3 text-sm">
      <div className="flex items-center gap-3">
        <Button onClick={run} disabled={busy}>
          {busy ? "Проверяю…" : "Проверить"}
        </Button>
        <span className="text-muted-foreground">Права, WinDivert, служба BFE, другие перехватчики, VPN, прокси, DoH.</span>
      </div>
      <ul className="flex flex-col gap-2">
        {checks?.map((c) => (
          <li key={c.name} className="rounded-md border p-3">
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
    <section className="flex flex-col gap-2 border-t pt-4">
      <span className="font-medium">DNS Windows</span>
      <ul className="text-muted-foreground">
        {state?.adapters.length === 0 && <li>Нет включённых адаптеров Ethernet или Wi-Fi.</li>}
        {state?.adapters.map((a) => (
          <li key={a.name}>
            {a.name}: {a.dns ? a.dns.replaceAll(",", ", ") : "автоматически (DHCP)"}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" disabled={busy || !state} onClick={apply}>
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

function Stat({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-2xl font-semibold tabular-nums">{value ?? 0}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
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
        className="rounded-md border bg-background px-3 py-2"
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
