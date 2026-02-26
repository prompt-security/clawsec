import React from 'react';
import { ExternalLink, PlayCircle } from 'lucide-react';
import { Footer } from '../components/Footer';

interface DemoVideo {
  id: string;
  title: string;
  description: string;
  videoSrc: string;
  posterSrc: string;
  videoContainerClassName?: string;
}

const demoVideos: DemoVideo[] = [
  {
    id: 'drift-demo',
    title: 'Drift Detection Demo (soul-guardian)',
    description:
      'Shows integrity monitoring in action: tamper detection, alerting, and restoration-oriented behavior for protected files.',
    videoSrc: '/video/soul-guardian-demo.mp4',
    posterSrc: '/video/soul-guardian-demo-poster.jpg',
  },
  {
    id: 'install-demo',
    title: 'Install Demo (clawsec-suite)',
    description:
      'Walkthrough of the one-command suite install flow and what gets configured for advisory monitoring and protection.',
    videoSrc: '/video/install-demo.mp4',
    posterSrc: '/video/install-demo-poster.jpg',
    videoContainerClassName: 'md:max-w-[50%]',
  },
];

export const ProductDemo: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto pt-[52px] space-y-10">
      <section className="text-center space-y-4">
        <h1 className="text-3xl md:text-4xl text-white flex items-center justify-center gap-3">
          <PlayCircle className="text-clawd-accent" />
          Watch It in Action
        </h1>
        <p className="text-gray-400 max-w-3xl mx-auto">
          Product demos for ClawSec installation and runtime protection behavior. These are the
          same demo assets referenced in the repository README, presented as playable videos.
        </p>
      </section>

      <section className="space-y-8">
        {demoVideos.map((demo) => (
          <article
            key={demo.id}
            className="bg-clawd-900 border border-clawd-700 rounded-xl overflow-hidden"
          >
            <div className="px-6 pt-6 pb-4 space-y-3">
              <h2 className="text-xl text-white">{demo.title}</h2>
              <p className="text-gray-400">{demo.description}</p>
            </div>
            <div className="px-6 pb-6 space-y-4">
              <div
                className={`rounded-lg overflow-hidden border border-clawd-700 bg-black ${
                  demo.videoContainerClassName ?? ''
                }`}
              >
                <video
                  className="w-full h-auto"
                  controls
                  playsInline
                  preload="metadata"
                  poster={demo.posterSrc}
                >
                  <source src={demo.videoSrc} type="video/mp4" />
                  Your browser does not support the video tag.
                </video>
              </div>
              <a
                href={demo.videoSrc}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 text-sm text-clawd-accent hover:underline"
              >
                <ExternalLink size={15} />
                Open video in new tab
              </a>
            </div>
          </article>
        ))}
      </section>

      <Footer />
    </div>
  );
};
