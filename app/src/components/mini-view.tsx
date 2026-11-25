import { CircleCheck, CircleDashed, Maximize2, Power, RefreshCw } from "lucide-react"

import { IconButton, WindowButtons } from "@/components/window-controls"
import { SERVICES, summarize, type SiteActivity } from "@/lib/services"
import logo from "../../src-tauri/icons/128x128.png"

// Мини-режим: узкое окно 340×620 — кнопка включения, модули, сервисы с полоской активности и три счётчика.

type Props = {
  running: boolean
  busy: boolean
  uptime: string
  settings: { auto: boolean; quic: "fake" | "drop" | "pass"; doh: string }
  dohServer: string | null
  stats?: { changed: number; dropped: number; dohOk: number }
  sites: SiteActivity[]
  verdicts: Record<string, "works" | "switched">
  tg: { running: boolean; active: number } | null
  error: string | null
  onToggle: () => void
  onExpand: () => void
}

export function MiniView(props: Props) {
  const { running, settings, stats, tg } = props
  const summary = summarize(props.sites, props.verdicts)
  const busiest = Math.max(1, ...Object.values(summary).map((s) => s.connections + s.dns))
  const tgOn = tg?.running ?? false

  const chips: [string, boolean][] = [
    [{ fake: "QUIC: фейк", drop: "QUIC отбрасывается", pass: "QUIC не трогается" }[settings.quic], running && settings.quic !== "pass"],
    [settings.doh === "off" ? "обычный DNS" : `DoH ${props.dohServer ?? settings.doh}`, running && settings.doh !== "off"],
    ["Telegram-прокси", tgOn],
  ]

  return (
    <div className="flex h-svh flex-col gap-3 p-3.5">
      <div data-tauri-drag-region className="flex items-center gap-2.5">
        <img src={logo} alt="" className="size-8 rounded-[10px]" />
        <b data-tauri-drag-region className="flex-1 text-base font-extrabold tracking-tight">
          Veyrix
        </b>
        <IconButton title="Обычный режим" icon={Maximize2} onClick={props.onExpand} size="sm" />
        <WindowButtons />
      </div>

      <section className="map-field flex flex-col items-center gap-2.5 rounded-[20px] border px-4 pt-5 pb-4">
        <button
          type="button"
          title={running ? "Остановить обход" : "Запустить обход"}
          aria-label={running ? "Остановить обход" : "Запустить обход"}
          disabled={props.busy}
          onClick={props.onToggle}
          className={`grid size-[92px] place-items-center rounded-full border-2 transition-all disabled:opacity-60 ${
            running
              ? "border-primary bg-[radial-gradient(circle_at_50%_40%,#1b4a2c,#0c2215)] text-primary shadow-[0_0_28px_rgb(57_240_122/0.35),inset_0_0_18px_rgb(57_240_122/0.15)]"
              : "border-[#3a3d3b] bg-[#161817] text-[#8b8f8c] hover:border-primary hover:text-primary"
          }`}
        >
          <Power className="size-[38px]" strokeWidth={2.2} />
        </button>
        <div className="text-[15px] font-extrabold">{running ? "Обход включён" : "Обход выключен"}</div>
        <div className="text-xs text-muted-foreground">
          {running ? `${props.uptime} · ${settings.auto ? "автоподбор приёма" : "приём по умолчанию"}` : "нажмите, чтобы включить"}
        </div>
        <div className="flex flex-wrap justify-center gap-1.5">
          {chips.map(([text, on]) => (
            <span
              key={text}
              className={`flex items-center gap-1.5 rounded-full border border-[#262827] bg-[#1c1e1d] px-2.5 py-1 text-[11.5px] font-semibold ${
                on ? "text-[#cfd2cf]" : "text-[#6d716e]"
              }`}
            >
              <i className={`inline-block size-1.5 rounded-full ${on ? "bg-primary" : "bg-[#5d615e]"}`} />
              {text}
            </span>
          ))}
        </div>
        {props.error && <p className="text-center text-xs text-destructive">{props.error}</p>}
      </section>

      <ul className="rounded-[18px] border bg-[#121413]/90 p-1.5">
        {SERVICES.map((svc) => {
          const s = summary[svc.id]
          const viaProxy = svc.id === "telegram" && tgOn
          const seen = s.connections + s.dns > 0 || viaProxy
          const note = s.switched
            ? "приём сменён"
            : viaProxy
              ? `${tg?.active ?? 0} соед.`
              : svc.id === "other"
                ? `${s.sites} сайт.`
                : seen
                  ? `${s.connections} соед.`
                  : "—"
          return (
            <li key={svc.id} className="flex items-center gap-2.5 border-[#1a1c1b] px-2.5 py-2 text-[13px] font-semibold not-first:border-t">
              <span style={{ color: seen ? svc.color : "#6d716e" }}>
                <svc.icon className="size-4" />
              </span>
              <span className={seen ? "" : "text-[#8b8f8c]"}>{svc.title}</span>
              <span className="ml-auto text-[11.5px] font-medium text-muted-foreground">{note}</span>
              <span className="h-1 w-11 overflow-hidden rounded-sm bg-[#232524]">
                <span
                  className="block h-full rounded-sm transition-all"
                  style={{
                    width: `${Math.round(((s.connections + s.dns) / busiest) * 100)}%`,
                    background: svc.color,
                    opacity: s.live ? 1 : 0.4,
                  }}
                />
              </span>
              {s.switched ? (
                <RefreshCw className="size-4 text-warning" />
              ) : seen ? (
                <CircleCheck className="size-4 text-primary" />
              ) : (
                <CircleDashed className="size-4 text-[#5d615e]" />
              )}
            </li>
          )
        })}
      </ul>

      <div className="grid grid-cols-3 gap-2">
        <MiniStat label="С приёмом" value={stats?.changed} />
        <MiniStat label="QUIC отброшено" value={stats?.dropped} />
        <MiniStat label="DNS через DoH" value={stats?.dohOk} />
      </div>
    </div>
  )
}

function MiniStat({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="rounded-[14px] border bg-[#141615]/85 px-2.5 py-2">
      <div className="truncate text-[10.5px] font-semibold text-muted-foreground">{label}</div>
      <div className="text-base font-extrabold tabular-nums">{(value ?? 0).toLocaleString("ru-RU")}</div>
    </div>
  )
}
