import React, { useState } from 'react';
import { NavLink } from 'react-router';
import { Menu, X, Terminal, Layers, Rss, Home, Github, BookOpenText, PlayCircle } from 'lucide-react';

export const Header: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);

  const navItems = [
    { label: 'Home', path: '/', icon: Home },
    { label: 'Skills', path: '/skills', icon: Layers },
    { label: 'Security Feed', path: '/feed', icon: Rss },
    { label: 'Product Demo', path: '/demo', icon: PlayCircle },
    { label: 'Wiki', path: '/wiki', icon: BookOpenText },
  ];

  const baseLink =
    'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all';

  const desktopNav = (
    <aside className="hidden md:flex w-64 flex-col border-r border-[#e8e6f2] bg-white/70 backdrop-blur-xl shadow-[20px_0_50px_rgba(11,12,27,0.04)] z-40 pt-[75px]">
      <nav className="overflow-y-auto px-4 pt-8 space-y-2">
        {navItems.map(({ label, path, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            className={({ isActive }) =>
              `${baseLink} ${
                isActive
                  ? 'bg-clawd-600/10 text-clawd-800 border border-clawd-600/20'
                  : 'text-gray-500 hover:text-clawd-800 hover:bg-black/5'
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
          className="mt-6 w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-clawd-green text-clawd-800 font-semibold border border-clawd-800 shadow-[0_12px_30px_rgba(143,255,8,0.3)] hover:bg-clawd-greenHover transition-colors"
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
      <header className="md:hidden fixed top-[72px] left-0 right-0 z-50 backdrop-blur-md bg-white/92 border-b border-[#e8e6f2]">
        <div className="px-4 h-14 flex items-center justify-between">
          <NavLink to="/" className="flex items-center gap-2 text-clawd-800 font-semibold text-lg">
            <img src="/img/favicon.ico" alt="" className="w-5 h-5 rounded-sm" />
            ClawSec
          </NavLink>
          <div className="flex items-center gap-3">
            <a
              href="https://github.com/prompt-security/clawsec"
              target="_blank"
              rel="noopener noreferrer"
              className="text-clawd-600 hover:text-clawd-500 transition-colors"
              aria-label="Open GitHub repository"
            >
              <Github size={21} />
            </a>
            <button
              className="text-gray-500 hover:text-clawd-800"
              onClick={() => setIsOpen(!isOpen)}
              aria-label="Toggle navigation"
            >
              {isOpen ? <X size={24} /> : <Menu size={24} />}
            </button>
          </div>
        </div>
        {isOpen && (
          <div className="bg-white/95 border-t border-[#e8e6f2] shadow-lg">
            <div className="flex flex-col p-4 space-y-3">
              {navItems.map(({ label, path, icon: Icon }) => (
                <NavLink
                  key={path}
                  to={path}
                  onClick={() => setIsOpen(false)}
                  className={({ isActive }) =>
                    `${baseLink} ${
                      isActive ? 'bg-clawd-600/10 text-clawd-800' : 'text-gray-500 hover:text-clawd-800 hover:bg-black/5'
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
                className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-clawd-green text-clawd-800 font-semibold border border-clawd-800 hover:bg-clawd-greenHover transition-colors"
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
