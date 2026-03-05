import { Outlet, Link, useLocation } from 'react-router-dom'
import { Terminal, Search, Users, Info } from 'lucide-react'

const navItems = [
  { path: '/', label: 'Scan', icon: Search },
  { path: '/community', label: 'Community', icon: Users },
  { path: '/about', label: 'About', icon: Info },
]

export default function Layout() {
  const { pathname } = useLocation()

  return (
    <div className="min-h-screen flex flex-col bg-grid scanline-overlay">
      {/* Header */}
      <header className="border-b border-[#1b2838] bg-[#0a0e17]/95 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="w-8 h-8 rounded-md border border-[#00ff41]/30 bg-[#00ff41]/5 flex items-center justify-center group-hover:bg-[#00ff41]/10 transition animate-pulse-glow">
              <Terminal className="w-4 h-4 text-[#00ff41]" />
            </div>
            <div className="font-mono">
              <span className="font-bold text-[#00ff41] glow-green text-sm tracking-wide">TRUSTLENS</span>
              <span className="text-[#00ffff] font-semibold text-[10px] ml-1 glow-cyan">AI</span>
            </div>
          </Link>

          <nav className="flex items-center gap-1">
            {navItems.map(({ path, label, icon: Icon }) => {
              const active = pathname === path
              return (
                <Link
                  key={path}
                  to={path}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono font-medium transition-all ${
                    active
                      ? 'text-[#00ff41] bg-[#00ff41]/8 border border-[#00ff41]/20 glow-green'
                      : 'text-[#484f58] hover:text-[#c9d1d9] hover:bg-white/3 border border-transparent'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">{label}</span>
                </Link>
              )
            })}
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1b2838] py-5">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] font-mono text-[#484f58]">
          <p className="flex items-center gap-2">
            <span className="text-[#00ff41]/60">$</span>
            <span>AI advises. Rules decide. Evidence explains.</span>
          </p>
          <div className="flex items-center gap-4">
            <a href="https://github.com/abhishekayu/TrustLens" target="_blank" rel="noreferrer" className="hover:text-[#00ff41] transition">GitHub</a>
            <a href="https://github.com/abhishekayu/TrustLens/blob/main/LICENSE" target="_blank" rel="noreferrer" className="hover:text-[#00ffff] transition">MIT License</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
