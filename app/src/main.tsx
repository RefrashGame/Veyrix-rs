import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import "./index.css"
import App from "./App.tsx"
import { ExternalLinkGuard } from "./components/external-link-guard.tsx"

// Тема одна — тёмная: класс dark задан в index.html.
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ExternalLinkGuard />
    <App />
  </StrictMode>
)
