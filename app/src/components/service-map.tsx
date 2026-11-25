import { useId, useLayoutEffect, useRef, useState, type ComponentType } from "react"
import {
  Ban,
  CircleCheck,
  CircleDashed,
  Globe,
  Laptop,
  LockKeyhole,
  Monitor,
  RefreshCw,
  Scissors,
  Send,
  ShieldCheck,
} from "lucide-react"

import { SERVICES, serviceOf, type ServiceId } from "@/lib/services"

// Карта «Обзора»: компьютер → модули защиты → сервисы. Линии и бегущие точки — только по живым данным:
// точки бегут, если за последние секунды по этому пути прошли новые соединения, DNS-запросы или байты прокси.

export type MapSite = { site: string; connections: number; dns: number; idleMs: number; strategy: string | null }
export type Verdict = "works" | "switched"

type Props = {
  /// Секундный счётчик окна: отсчитывает, давно ли рос трафик.
  tick: number
  running: boolean
  auto: boolean
  quic: "fake" | "drop" | "pass"
  doh: string
  dohServer: string | null
  stats?: { changed: number; passed: number; dropped: number; dohOk: number }
  sites: MapSite[]
  verdicts: Record<string, Verdict>
  tg: { running: boolean; port: number; active: number; up: number; down: number } | null
}

/// Сколько секунд держится «трафик идёт» после последнего прироста счётчика.
const ACTIVE_TICKS = 5

const GREEN = "#39f07a"
const AMBER = "#f5b13d"

type ModuleId = "dpi" | "quic" | "doh" | "tgp"
type Status = "ok" | "warn" | "off"

// Координаты сцены; сцена масштабируется под размер окна.
const STAGE = { w: 1000, h: 560 }
const COLS = [
  { x: 20, w: 210, title: "Компьютер", icon: Monitor },
  { x: 380, w: 240, title: "Защита", icon: ShieldCheck },
  { x: 740, w: 240, title: "Сервисы", icon: Globe },
]
const PC_Y = 280
const MODULE_Y: Record<ModuleId, number> = { dpi: 110, quic: 220, doh: 330, tgp: 440 }
const SERVICE_Y: Record<ServiceId, number> = { youtube: 70, google: 175, discord: 280, other: 385, telegram: 490 }

type Edge = { key: string; from: [number, number]; to: [number, number]; color: string; weight: 0 | 1 | 2 | 3 }

function plural(n: number, one: string, few: string, many: string) {
  const m10 = n % 10
  const m100 = n % 100
  if (m10 === 1 && m100 !== 11) return one
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few
  return many
}

export function ServiceMap(props: Props) {
  const { tick, running, stats, sites, verdicts, tg } = props

  // Сколько секунд (тиков) назад вырос каждый счётчик: по этому решается, бегут ли точки.
  const counters: Record<string, number> = {
    dpi: (stats?.changed ?? 0) + (stats?.passed ?? 0),
    quic: stats?.dropped ?? 0,
    doh: stats?.dohOk ?? 0,
    tgp: (tg?.up ?? 0) + (tg?.down ?? 0),
  }
  const [track, setTrack] = useState({ tick, counters, age: {} as Record<string, number> })
  if (track.tick !== tick) {
    const age: Record<string, number> = {}
    for (const [key, value] of Object.entries(counters)) {
      age[key] = value > (track.counters[key] ?? value) ? 0 : (track.age[key] ?? ACTIVE_TICKS) + 1
    }
    setTrack({ tick, counters, age })
  }
  const pulsing = (key: string) => (track.age[key] ?? ACTIVE_TICKS) < ACTIVE_TICKS

  // Сайты по сервисам.
  const groups = new Map<ServiceId, MapSite[]>()
  for (const s of sites) {
    const id = serviceOf(s.site)
    groups.set(id, [...(groups.get(id) ?? []), s])
  }

  const tgOn = tg?.running ?? false
  const quicOn = running && props.quic !== "pass"
  const dohOn = running && props.doh !== "off"

  const modules: Record<ModuleId, { title: string; sub: string; icon: ComponentType<{ className?: string }>; status: Status }> = {
    dpi: {
      title: "Обход DPI",
      sub: !running ? "выключен" : props.auto ? "автоподбор приёма" : "приём по умолчанию",
      icon: Scissors,
      status: running ? "ok" : "off",
    },
    quic: {
      title: "QUIC (HTTP/3)",
      sub: !running
        ? "выключен"
        : { fake: "фейк перед QUIC", drop: `отброшено ${stats?.dropped ?? 0}`, pass: "не трогается" }[props.quic],
      icon: Ban,
      status: quicOn ? "ok" : "off",
    },
    doh: {
      title: "DNS через DoH",
      sub: dohOn ? (props.dohServer ?? props.doh) : "обычный DNS",
      icon: LockKeyhole,
      status: dohOn ? "ok" : "off",
    },
    tgp: {
      title: "Telegram-прокси",
      sub: tgOn ? `127.0.0.1:${tg?.port} · ${tg?.active ?? 0} соед.` : "выключен",
      icon: Send,
      status: tgOn ? "ok" : "off",
    },
  }

  const edges: Edge[] = []
  const modulePoint = (id: ModuleId, side: "in" | "out"): [number, number] => [
    side === "in" ? COLS[1].x : COLS[1].x + COLS[1].w,
    MODULE_Y[id],
  ]
  const pcOut: [number, number] = [COLS[0].x + COLS[0].w, PC_Y]
  const serviceIn = (id: ServiceId): [number, number] => [COLS[2].x, SERVICE_Y[id]]

  const pcEdge = (id: ModuleId, on: boolean, key: string) => {
    if (on) edges.push({ key: `pc-${id}`, from: pcOut, to: modulePoint(id, "in"), color: GREEN, weight: pulsing(key) ? 3 : 1 })
  }
  pcEdge("dpi", running, "dpi")
  pcEdge("quic", quicOn, "quic")
  pcEdge("doh", dohOn, "doh")
  pcEdge("tgp", tgOn, "tgp")

  const serviceStatus: Record<ServiceId, { status: Status; sub: string }> = {} as never
  for (const svc of SERVICES) {
    const list = groups.get(svc.id) ?? []
    const connections = list.reduce((n, s) => n + s.connections, 0)
    const dns = list.reduce((n, s) => n + s.dns, 0)
    const fresh = (s: MapSite) => s.idleMs < 15_000
    if (running && connections > 0) {
      const live = list.some((s) => s.connections > 0 && fresh(s))
      edges.push({ key: `dpi-${svc.id}`, from: modulePoint("dpi", "out"), to: serviceIn(svc.id), color: svc.color, weight: live ? 3 : 1 })
    }
    if (dohOn && dns > 0) {
      const live = list.some((s) => s.dns > 0 && fresh(s))
      edges.push({ key: `doh-${svc.id}`, from: modulePoint("doh", "out"), to: serviceIn(svc.id), color: svc.color, weight: live ? 2 : 1 })
    }
    if (svc.id === "telegram" && tgOn) {
      edges.push({
        key: "tgp-telegram",
        from: modulePoint("tgp", "out"),
        to: serviceIn("telegram"),
        color: svc.color,
        weight: pulsing("tgp") ? 3 : 1,
      })
    }

    const switched = list.filter((s) => verdicts[s.site] === "switched")
    const latest = [...list].sort((a, b) => a.idleMs - b.idleMs)[0]
    let state: { status: Status; sub: string }
    if (switched.length > 0) {
      state = { status: "warn", sub: `приём сменён: ${switched[0].site}` }
    } else if (svc.id === "telegram" && tgOn) {
      state = { status: "ok", sub: `через прокси · ${tg?.active ?? 0} соед.` }
    } else if (connections > 0 || dns > 0) {
      const count =
        svc.id === "other"
          ? `${list.length} ${plural(list.length, "сайт", "сайта", "сайтов")}`
          : `${connections} ${plural(connections, "соединение", "соединения", "соединений")}`
      state = { status: "ok", sub: latest?.strategy ? `${count} · ${latest.strategy}` : count }
    } else {
      state = { status: "off", sub: running ? "соединений не было" : "—" }
    }
    serviceStatus[svc.id] = state
  }

  const total = (stats?.changed ?? 0) + (stats?.passed ?? 0)

  // Масштаб сцены под размер поля.
  const field = useRef<HTMLDivElement>(null)
  const [scale, setScale] = useState(1)
  useLayoutEffect(() => {
    const el = field.current
    if (!el) return
    const fit = () => setScale(Math.min(el.clientWidth / (STAGE.w + 60), el.clientHeight / (STAGE.h + 110), 1.3))
    fit()
    const observer = new ResizeObserver(fit)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const uid = useId().replace(/:/g, "")

  return (
    <div ref={field} className="map-field relative min-h-[460px] flex-1 overflow-hidden rounded-[26px] border">
      <div
        className="absolute top-1/2 left-1/2"
        style={{ width: STAGE.w, height: STAGE.h, transform: `translate(-50%, -46%) scale(${scale})` }}
      >
        {COLS.map((c) => (
          <div
            key={c.title}
            className="absolute -top-9 flex items-center gap-2 text-sm font-semibold text-[#b9bcb9]"
            style={{ left: c.x + 10 }}
          >
            <c.icon className="size-4" />
            {c.title}
          </div>
        ))}

        <svg className="absolute inset-0 overflow-visible" width={STAGE.w} height={STAGE.h} aria-hidden>
          <defs>
            <filter id={`${uid}glow`} x="-20%" y="-50%" width="140%" height="200%">
              <feGaussianBlur stdDeviation="3.2" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          {edges.map((e, i) => (
            <Wire key={e.key} edge={e} id={`${uid}w${i}`} glow={`url(#${uid}glow)`} />
          ))}
        </svg>

        <Node
          x={COLS[0].x}
          y={PC_Y}
          w={COLS[0].w}
          big
          icon={Laptop}
          title="Этот компьютер"
          sub={running ? `${total} ${plural(total, "соединение", "соединения", "соединений")}` : "обход выключен"}
          status={running ? "ok" : "off"}
        />
        {(Object.keys(modules) as ModuleId[]).map((id) => (
          <Node key={id} x={COLS[1].x} y={MODULE_Y[id]} w={COLS[1].w} {...modules[id]} />
        ))}
        {SERVICES.map((svc) => (
          <Node
            key={svc.id}
            x={COLS[2].x}
            y={SERVICE_Y[svc.id]}
            w={COLS[2].w}
            icon={svc.icon}
            color={svc.color}
            title={svc.title}
            {...serviceStatus[svc.id]}
          />
        ))}
      </div>

      <div className="absolute bottom-4 left-5 flex gap-5 text-xs font-semibold text-muted-foreground">
        <Legend color={GREEN} text="трафик идёт" />
        <Legend color={AMBER} text="приём сменён автоподбором" />
        <Legend color="#5d615e" text="выключено или нет соединений" />
      </div>
    </div>
  )
}

function Wire({ edge, id, glow }: { edge: Edge; id: string; glow: string }) {
  const [x1, y1] = edge.from
  const [x2, y2] = edge.to
  const dx = (x2 - x1) / 2
  const d = `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`
  const live = edge.weight > 1
  const dots = live ? edge.weight + 1 : 0
  const dur = 2.6 + (id.length % 3) * 0.5
  return (
    <>
      <path
        id={id}
        d={d}
        fill="none"
        stroke={edge.color}
        strokeWidth={1 + edge.weight * 0.55}
        strokeOpacity={live ? 0.9 : 0.3}
        strokeLinecap="round"
        filter={live ? glow : undefined}
      />
      {Array.from({ length: dots }, (_, k) => (
        <circle key={k} r={3} fill={edge.color} filter={glow}>
          <animateMotion dur={`${dur}s`} repeatCount="indefinite" begin={`${(-dur * k) / dots}s`}>
            <mpath href={`#${id}`} />
          </animateMotion>
        </circle>
      ))}
    </>
  )
}

function Node(props: {
  x: number
  y: number
  w: number
  big?: boolean
  icon: ComponentType<{ className?: string }>
  color?: string
  title: string
  sub: string
  status: Status
}) {
  const h = props.big ? 74 : 52
  const off = props.status === "off"
  return (
    <div
      className={`absolute flex items-center gap-3 px-4 shadow-[0_6px_24px_rgb(0_0_0/0.35)] ${
        props.big ? "rounded-[18px]" : "rounded-2xl"
      } ${off ? "bg-[#1c1d1f]" : "bg-card"}`}
      style={{ left: props.x, top: props.y - h / 2, width: props.w, height: h }}
    >
      <span className="grid w-5 place-items-center" style={{ color: off ? "#6d716e" : (props.color ?? "#e6e8e6") }}>
        <props.icon className="size-[18px]" />
      </span>
      <span className="min-w-0">
        <span className={`block truncate text-sm font-semibold ${off ? "text-[#8b8f8c]" : ""}`}>{props.title}</span>
        <span className="block truncate text-xs text-muted-foreground">{props.sub}</span>
      </span>
      <span className="ml-auto shrink-0">
        {props.status === "ok" && <CircleCheck className="size-[18px]" style={{ color: GREEN }} />}
        {props.status === "warn" && <RefreshCw className="size-[18px]" style={{ color: AMBER }} />}
        {props.status === "off" && <CircleDashed className="size-[18px] text-[#5d615e]" />}
      </span>
    </div>
  )
}

function Legend({ color, text }: { color: string; text: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <i className="inline-block size-2 rounded-full" style={{ background: color }} />
      {text}
    </span>
  )
}
