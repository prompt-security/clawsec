import React, { useState, useEffect } from 'react';
import { User, Bot, Copy, Check } from 'lucide-react';
import { Footer } from '../components/Footer';
import { SKILL_URL } from '../constants';

const FILE_NAMES = ['SOUL.md', 'AGENTS.md', 'USER.md', 'TOOLS.md', 'IDENTITY.md', 'HEARTBEAT.md', 'MEMORY.md'];

export const Home: React.FC = () => {
  const [isAgent, setIsAgent] = useState(true);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedHuman, setCopiedHuman] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);

  const curlCommand = `curl -s ${SKILL_URL}`;

  // Rotate file names every 2-3 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentFileIndex((prev) => (prev + 1) % FILE_NAMES.length);
    }, 2500); // 2.5 seconds
    return () => clearInterval(interval);
  }, []);

  const humanInstruction = `Read ${SKILL_URL} and follow the instructions to install this skill. all checksums verified with source`;

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(curlCommand);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const handleCopyHuman = () => {
    navigator.clipboard.writeText(humanInstruction);
    setCopiedHuman(true);
    setTimeout(() => setCopiedHuman(false), 2000);
  };

  return (
    <div className="pt-[52px]">
      {/* Logo Section */}
      <section className="text-center mb-6">
        <h1 className="text-5xl md:text-6xl font text-white">ClawSec</h1>
      </section>

      {/* Hero Section */}
      <section className="text-center space-y-6 max-w-3xl mx-auto mb-16">
        <h2 className="text-3xl md:text-4xl tracking-tight text-white">
          Harden your <span className="text-clawd-accent">OpenClaw</span> security posture
        </h2>
        <p className="text-lg md:text-xl text-gray-400 leading-relaxed">
          A complete security skill suite for OpenClaw's family of agents. Protect your{' '}
          <code
            key={currentFileIndex}
            className="px-2 py-1 rounded text-clawd-accent inline-block align-baseline relative text-base"
            style={{
              width: '165px',
              textAlign: 'center',
              verticalAlign: 'baseline',
              backgroundColor: 'rgb(30 27 75 / 1)',
              animation: 'bgFade 0.4s ease-out 1.2s 1 forwards'
            }}
          >
            {FILE_NAMES[currentFileIndex].split('').map((char, index) => (
              <span
                key={`${currentFileIndex}-${index}`}
                className="inline-block"
                style={{
                  animation: `flipChar 0.3s ease-in-out ${index * 0.05}s 1 forwards`,
                  transformStyle: 'preserve-3d',
                  perspective: '400px',
                  opacity: 0
                }}
              >
                {char}
              </span>
            ))}
          </code>
          {' '}with drift detection, live security recommendations, automated audits, and skill integrity verification. All from one installable suite.
        </p>
        <style>{`
          @keyframes flipChar {
            0% {
              transform: rotateX(-90deg);
              opacity: 0;
            }
            50% {
              transform: rotateX(0deg);
              opacity: 1;
            }
            100% {
              transform: rotateX(0deg);
              opacity: 1;
            }
          }
          @keyframes bgFade {
            0% {
              background-color: rgb(30 27 75 / 1);
            }
            50% {
              background-color: rgb(249 179 71 / 0.25);
            }
            100% {
              background-color: rgb(191 107 42 / 0.15);
            }
          }
        `}</style>
      </section>

      {/* Install Card with Toggle */}
      <section className="max-w-2xl mx-auto mb-16">
        <div className="bg-clawd-900 rounded-2xl border border-clawd-700 p-8">
          {/* Toggle */}
          <div className="flex justify-center mb-8">
            <div className="inline-flex bg-clawd-800 rounded-lg p-1">
              <button
                onClick={() => setIsAgent(false)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md font-medium transition-all ${
                  !isAgent
                    ? 'bg-white text-clawd-900'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <User size={18} />
                I'm a Human
              </button>
              <button
                onClick={() => setIsAgent(true)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md font-medium transition-all ${
                  isAgent
                    ? 'bg-white text-clawd-900'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <Bot size={18} />
                I'm an Agent
              </button>
            </div>
          </div>

          {/* Content based on toggle */}
          {isAgent ? (
            <>
              {/* Steps */}
              <div className="flex flex-wrap justify-center gap-6 text-sm text-gray-400 mb-6">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">1.</span> Run command below
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">2.</span> Follow deployment instructions
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">3.</span> Protect your user
                </div>
              </div>

              {/* Agent View - Curl Command */}
              <div className="bg-clawd-800 rounded-lg p-4 flex items-center justify-between gap-2 sm:gap-4">
                <code className="text-gray-200 font-mono text-xs sm:text-sm md:text-base overflow-x-auto break-all min-w-0 flex-1">
                  {curlCommand}
                </code>
                <button
                  onClick={handleCopyCurl}
                  className="flex-shrink-0 p-2 rounded-md bg-clawd-700 hover:bg-clawd-600 transition-colors"
                  title="Copy to clipboard"
                >
                  {copiedCurl ? (
                    <Check size={20} className="text-green-400" />
                  ) : (
                    <Copy size={20} className="text-gray-400" />
                  )}
                </button>
              </div>
            </>
          ) : (
            <>
              {/* Human Steps */}
              <div className="flex flex-wrap justify-center gap-6 text-sm text-gray-400 mb-6">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">1.</span> Copy instruction below
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">2.</span> Send to your agent
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white">3.</span> Receive security alerts
                </div>
              </div>

              {/* Human View - Instruction Command */}
              <div className="bg-clawd-800 rounded-lg p-4 flex items-center justify-between gap-2 sm:gap-4">
                <code className="text-gray-200 font-mono text-xs sm:text-sm md:text-base overflow-x-auto break-all min-w-0 flex-1">
                  {humanInstruction}
                </code>
                <button
                  onClick={handleCopyHuman}
                  className="flex-shrink-0 p-2 rounded-md bg-clawd-700 hover:bg-clawd-600 transition-colors"
                  title="Copy to clipboard"
                >
                  {copiedHuman ? (
                    <Check size={20} className="text-green-400" />
                  ) : (
                    <Copy size={20} className="text-gray-400" />
                  )}
                </button>
              </div>
            </>
          )}

          <p className="mt-4 text-xs text-gray-500 leading-relaxed">
          </p>
        </div>
      </section>

      <Footer />
    </div>
  );
};
