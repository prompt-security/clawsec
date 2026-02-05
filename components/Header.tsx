import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Menu, X, Terminal, Layers, Rss, Home } from 'lucide-react';

export const Header: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);

  const navItems = [
    { label: 'Home', path: '/', icon: Home },
    { label: 'Skills', path: '/skills', icon: Layers },
    { label: 'Security Feed', path: '/feed', icon: Rss },
  ];

  const baseLink =
    'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all';

  const desktopNav = (
    <aside className="hidden md:flex w-64 flex-col border-r border-[#3a1f7a] bg-gradient-to-b from-[#26115d]/95 via-[#3a1f7a]/92 to-[#523899]/90 backdrop-blur-xl shadow-[20px_0_50px_rgba(0,0,0,0.35)] z-40 pt-[75px]">
      <nav className="overflow-y-auto px-4 pt-8 space-y-2">
        {navItems.map(({ label, path, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            className={({ isActive }) =>
              `${baseLink} ${
                isActive
                  ? 'bg-white/10 text-white shadow-[0_10px_25px_rgba(0,0,0,0.25)] border border-white/10'
                  : 'text-gray-400 hover:text-white hover:bg-white/5'
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
          </NavLink>
        ))}

        <a
          href="https://github.com/prompt-security/clawsec"
          target="_blank"
          rel="noopener noreferrer"
          className="mt-6 w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-clawd-accent text-[#27125d] font-semibold shadow-[0_12px_30px_rgba(255,162,63,0.35)] hover:bg-clawd-accentHover transition-colors"
        >
          <Terminal size={16} />
          GitHub
        </a>
      </nav>
    </aside>
  );

  return (
    <>
      {desktopNav}

      {/* Mobile top bar */}
      <header className="md:hidden fixed top-0 left-0 right-0 z-50 backdrop-blur-md bg-[#26115d]/92 border-b border-[#3a1f7a]">
        <div className="px-4 h-14 flex items-center justify-between">
          <NavLink to="/" className="flex items-center gap-2 text-white font-semibold text-lg">
            <Shield className="w-5 h-5 text-clawd-accent" />
            ClawSec
          </NavLink>
          <button
            className="text-gray-300 hover:text-white"
            onClick={() => setIsOpen(!isOpen)}
            aria-label="Toggle navigation"
          >
            {isOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
        {isOpen && (
          <div className="bg-[#26115d]/95 border-t border-[#3a1f7a] shadow-lg">
            <div className="flex flex-col p-4 space-y-3">
              {navItems.map(({ label, path, icon: Icon }) => (
                <NavLink
                  key={path}
                  to={path}
                  onClick={() => setIsOpen(false)}
                  className={({ isActive }) =>
                    `${baseLink} ${
                      isActive ? 'bg-white/10 text-white' : 'text-gray-400 hover:text-white hover:bg-white/5'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </NavLink>
              ))}
              <a
                href="https://github.com/prompt-security/clawsec"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-clawd-accent text-[#27125d] font-semibold hover:bg-clawd-accentHover transition-colors"
              >
                <Terminal size={16} />
                GitHub
              </a>
            </div>
          </div>
        )}
      </header>
    </>
  );
};
