import React from 'react';
import { Header } from './Header';
import { LobsterBackground } from './LobsterBackground';

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="min-h-screen font-sans text-slate-50 relative overflow-x-hidden w-full max-w-full">
      <LobsterBackground />
      <div className="relative z-10 flex min-h-screen w-full max-w-full">
        <Header />
        <main className="flex-1 min-w-0 px-4 sm:px-6 lg:px-10 pt-24 pb-20 md:pt-16 md:pb-12 overflow-x-hidden">
          <div className="max-w-6xl mx-auto w-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};
