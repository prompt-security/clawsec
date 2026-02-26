import React from 'react';
import type { Components } from 'react-markdown';

export const defaultMarkdownComponents: Components = {
  h1: ({ children }) => (
    <h1 className="text-2xl font-bold text-white border-b border-clawd-700 pb-3 mb-6 mt-0">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2 className="text-xl font-bold text-white mt-8 mb-4">{children}</h2>
  ),
  h3: ({ children }) => (
    <h3 className="text-lg font-semibold text-white mt-6 mb-3">{children}</h3>
  ),
  h4: ({ children }) => (
    <h4 className="text-base font-semibold text-white mt-4 mb-2">{children}</h4>
  ),
  p: ({ children }) => (
    <p className="text-gray-300 leading-relaxed mb-4">{children}</p>
  ),
  a: ({ href, children }) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-clawd-accent hover:underline"
    >
      {children}
    </a>
  ),
  ul: ({ children }) => (
    <ul className="list-disc list-inside text-gray-300 space-y-2 mb-4 ml-4">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="list-decimal list-inside text-gray-300 space-y-2 mb-4 ml-4">
      {children}
    </ol>
  ),
  li: ({ children }) => (
    <li className="text-gray-300">{children}</li>
  ),
  blockquote: ({ children }) => (
    <blockquote className="border-l-4 border-clawd-accent pl-4 py-2 my-4 bg-clawd-900/50 rounded-r text-gray-400 italic">
      {children}
    </blockquote>
  ),
  code: ({ className, children }) => {
    const isInline = !className;
    if (isInline) {
      return (
        <code className="text-orange-300 bg-clawd-900 px-1.5 py-0.5 rounded text-sm font-mono">
          {children}
        </code>
      );
    }
    return (
      <code className="text-gray-200 text-sm font-mono">{children}</code>
    );
  },
  pre: ({ children }) => (
    <pre className="bg-clawd-900 border border-clawd-700 rounded-lg p-3 sm:p-4 overflow-x-auto mb-4 text-xs sm:text-sm max-w-full">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="overflow-x-auto mb-6 -mx-4 sm:mx-0 px-4 sm:px-0">
      <table className="w-full border-collapse text-xs sm:text-sm min-w-[300px]">
        {children}
      </table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="bg-clawd-900 border-b border-clawd-600">
      {children}
    </thead>
  ),
  tbody: ({ children }) => <tbody>{children}</tbody>,
  tr: ({ children }) => (
    <tr className="border-b border-clawd-700/50">{children}</tr>
  ),
  th: ({ children }) => (
    <th className="text-left px-4 py-3 text-gray-300 font-semibold">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="px-4 py-3 text-gray-300">{children}</td>
  ),
  hr: () => <hr className="border-clawd-700 my-6" />,
  strong: ({ children }) => (
    <strong className="text-white font-semibold">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="text-gray-200">{children}</em>
  ),
};
