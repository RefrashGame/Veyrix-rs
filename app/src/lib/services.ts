// Сервисы на карте «Обзора» и в мини-режиме: ключ сайта от движка (домен 2-го уровня) → сервис.

import type { ComponentType } from "react"
import { Layers, MessageCircle, MonitorPlay, Search, Send } from "lucide-react"

export type ServiceId = "youtube" | "google" | "discord" | "telegram" | "other"

/// Порядок — как на карте сверху вниз.
export const SERVICES: { id: ServiceId; title: string; icon: ComponentType<{ className?: string }>; color: string }[] = [
  { id: "youtube", title: "YouTube", icon: MonitorPlay, color: "#ff3b5c" },
  { id: "google", title: "Google", icon: Search, color: "#3d8bff" },
  { id: "discord", title: "Discord", icon: MessageCircle, color: "#8b7bff" },
  { id: "other", title: "Другие сайты", icon: Layers, color: "#c9ccc9" },
  { id: "telegram", title: "Telegram", icon: Send, color: "#2ab4ff" },
]

const DOMAINS: Record<Exclude<ServiceId, "other">, string[]> = {
  youtube: ["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com", "youtube-nocookie.com"],
  google: [
    "google.com",
    "google.ru",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "gvt1.com",
    "gvt2.com",
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
  ],
  discord: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"],
  telegram: ["telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com"],
}

const BY_SITE = new Map<string, ServiceId>(
  Object.entries(DOMAINS).flatMap(([id, sites]) => sites.map((site) => [site, id as ServiceId] as const)),
)

export function serviceOf(site: string): ServiceId {
  return BY_SITE.get(site) ?? "other"
}

export type SiteActivity = { site: string; connections: number; dns: number; idleMs: number }

export type ServiceSummary = {
  connections: number
  dns: number
  sites: number
  /// Сайт сервиса, для которого автоподбор сменил приём.
  switched: string | null
  /// Было соединение или DNS-запрос за последние 15 с.
  live: boolean
}

/// Итоги по сервисам для мини-режима.
export function summarize(
  sites: SiteActivity[],
  verdicts: Record<string, "works" | "switched">,
): Record<ServiceId, ServiceSummary> {
  const empty = (): ServiceSummary => ({ connections: 0, dns: 0, sites: 0, switched: null, live: false })
  const out: Record<ServiceId, ServiceSummary> = {
    youtube: empty(),
    google: empty(),
    discord: empty(),
    telegram: empty(),
    other: empty(),
  }
  for (const s of sites) {
    const sum = out[serviceOf(s.site)]
    sum.connections += s.connections
    sum.dns += s.dns
    sum.sites += 1
    if (verdicts[s.site] === "switched") sum.switched ??= s.site
    if (s.idleMs < 15_000) sum.live = true
  }
  return out
}
