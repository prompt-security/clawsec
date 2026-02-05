import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="text-center py-6 mt-auto">
      <p className="text-gray-300 text-sm italic">
        ClawSec is a project by Prompt Security, a SentinelOne company. It's not affiliated with OpenClaw. Designed for security research and agentic workflow hardening.
      </p>
      <div className="flex justify-center gap-4 mt-4">
        <span className="text-2xl animate-pulse">🦞</span>
      </div>
    </footer>
  );
};
