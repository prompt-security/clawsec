import React from 'react';
import { useLocation } from 'react-router';

export const LobsterBackground: React.FC = () => {
  const { pathname } = useLocation();
  const isHome = pathname === '/';

  return (
    <>
      {/* Angular motif inspired by Prompt "A", held in the viewport. Painted
          first so the gradients below cover it rather than it streaking
          across the purple apex. */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none">
        <div className="absolute right-[-5%] bottom-[10%] w-[59.8vw] h-[59.8vw] opacity-40">
          <img
            src="/img/prompt_line.svg"
            loading="lazy"
            alt=""
            className="w-full h-full object-contain"
          />
        </div>
      </div>

      {/* Spans the full document, so the grid runs the whole length of the page */}
      <div className="absolute inset-0 pointer-events-none z-0 overflow-hidden select-none">
        <div className="ps-grid absolute inset-0" />
        <div className="ps-wash absolute inset-x-0 top-0" />
        {isHome && <div className="ps-break absolute inset-x-0" />}
      </div>
    </>
  );
};
