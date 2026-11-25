import type { ComponentType, ReactNode } from "react"
import { Minus, X } from "lucide-react"

import { trackedInvoke as invoke } from "@/lib/tauri"

// У окна нет рамки Windows: «свернуть» и «закрыть» — свои кнопки. Закрыть = спрятать в трей, как раньше крестик.

export function WindowButtons() {
  return (
    <div className="flex items-center gap-1">
      <IconButton title="Свернуть" icon={Minus} onClick={() => invoke("window_minimize").catch(() => {})} plain />
      <IconButton
        title="Закрыть в трей — обход продолжит работать"
        icon={X}
        onClick={() => invoke("window_hide").catch(() => {})}
        plain
        danger
      />
    </div>
  )
}

export function IconButton(props: {
  title: string
  icon: ComponentType<{ className?: string }>
  onClick: () => void
  /// Без рамки и фона — для кнопок окна.
  plain?: boolean
  danger?: boolean
  size?: "sm" | "md"
  children?: ReactNode
}) {
  const size = props.size === "sm" ? "size-8" : "size-10"
  const look = props.plain
    ? `text-[#9a9e9b] hover:text-foreground ${props.danger ? "hover:bg-destructive/80" : "hover:bg-white/10"}`
    : "border bg-[#141615] text-[#d6d9d6] hover:border-primary hover:text-primary"
  return (
    <button
      type="button"
      title={props.title}
      aria-label={props.title}
      onClick={props.onClick}
      className={`grid shrink-0 place-items-center rounded-full transition-colors ${size} ${look}`}
    >
      <props.icon className={props.size === "sm" ? "size-4" : "size-[18px]"} />
    </button>
  )
}
