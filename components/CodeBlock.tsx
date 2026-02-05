import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeBlockProps {
  code: string;
  language?: string;
  label?: string;
  className?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, language = 'bash', label, className }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`my-4 rounded-lg overflow-hidden border border-clawd-700 bg-clawd-800 shadow-xl ${className || ''}`}>
      <div className="flex items-center justify-between px-4 py-2 bg-clawd-900 border-b border-clawd-700">
        <span className="text-xs font-mono text-gray-400 uppercase">{label || language}</span>
        <button 
          onClick={handleCopy}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors"
          aria-label="Copy code"
        >
          {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div className="p-3 sm:p-4 overflow-x-auto max-w-full">
        <pre className="text-xs sm:text-sm font-mono text-gray-300 whitespace-pre-wrap break-all overflow-wrap-anywhere">
          <code>{code}</code>
        </pre>
      </div>
    </div>
  );
};