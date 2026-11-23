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
    return () => {
      unlisten.then((stop) => stop())
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
          <TabsTrigger value="settings">Настройки</TabsTrigger>
        </TabsList>

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
