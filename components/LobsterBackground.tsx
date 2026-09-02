import React from 'react';
import { useLocation } from 'react-router';

export const LobsterBackground: React.FC = () => {
  const { pathname } = useLocation();
  const isHome = pathname === '/';

  // Spans the full document, so the grid runs the whole length of the page
  return (
    <div
      className="absolute inset-0 pointer-events-none z-0 overflow-hidden select-none"
      aria-hidden="true"
    >
      <div className="ps-grid absolute inset-0" />
      <div className="ps-wash absolute inset-x-0 top-0" />
      {isHome && <div className="ps-break absolute inset-x-0" />}
    </div>
  );
};
