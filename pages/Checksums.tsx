import { useEffect, useState } from 'react';
import { Shield, Copy, Download, CheckCircle2 } from 'lucide-react';
import { CodeBlock } from '../components/CodeBlock';

interface FileChecksum {
  sha256: string;
  size: number;
  url: string;
}

interface ChecksumsData {
  version: string;
  generated_at: string;
  repository: string;
  files: Record<string, FileChecksum>;
}

export default function Checksums() {
  const [checksums, setChecksums] = useState<ChecksumsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    fetch('./checksums.json')
      .then(res => {
        if (!res.ok) throw new Error('Not found');
        return res.json();
      })
      .then(data => {
        setChecksums(data);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const fileDescriptions: Record<string, string> = {
    'SKILL.md': 'Main ClawSec skill documentation',
    'heartbeat.md': 'Heartbeat monitoring and update instructions',
    'reporting.md': 'Security incident reporting guidelines',
    'skill.json': 'Skill metadata and configuration',
    'feed.json': 'Community security advisory feed'
  };

  return (
    <>
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-12 text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-12 h-12 text-clawd-accent" />
            <h1 className="text-4xl font-bold">File Checksums</h1>
          </div>
          <p className="text-xl text-gray-300">
            Verify the integrity of ClawSec files before use
          </p>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-clawd-accent"></div>
            <p className="mt-4 text-gray-400">Loading checksums...</p>
          </div>
        ) : checksums ? (
          <>
            {/* Version Info */}
            <div className="bg-clawd-800 rounded-lg p-6 mb-8">
              <div className="grid md:grid-cols-3 gap-4 text-sm">
                <div>
                  <div className="text-gray-400 mb-1">Version</div>
                  <div className="font-mono text-clawd-accent">{checksums.version}</div>
                </div>
                <div>
                  <div className="text-gray-400 mb-1">Generated</div>
                  <div className="font-mono">{new Date(checksums.generated_at).toLocaleString()}</div>
                </div>
                <div>
                  <div className="text-gray-400 mb-1">Repository</div>
                  <div className="font-mono text-sm">{checksums.repository}</div>
                </div>
              </div>
            </div>

            {/* Files Table */}
            <div className="bg-clawd-800 rounded-lg overflow-hidden mb-8">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-clawd-900">
                    <tr>
                      <th className="px-6 py-4 text-left text-sm font-semibold">File</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold">Size</th>
                      <th className="px-6 py-4 text-left text-sm font-semibold">SHA256 Checksum</th>
                      <th className="px-6 py-4 text-right text-sm font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-clawd-700">
                    {(Object.entries(checksums.files) as [string, FileChecksum][]).map(([filename, data]) => (
                      <tr key={filename} className="hover:bg-clawd-700/50 transition-colors">
                        <td className="px-6 py-4">
                          <div className="font-mono text-sm text-clawd-accent">{filename}</div>
                          <div className="text-xs text-gray-400 mt-1">
                            {fileDescriptions[filename] || 'ClawSec file'}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm">{(data.size / 1024).toFixed(1)} KB</div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="font-mono text-xs break-all max-w-md">
                            {data.sha256}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => copyToClipboard(data.sha256, filename)}
                              className="p-2 hover:bg-clawd-900 rounded transition-colors"
                              title="Copy checksum"
                            >
                              {copied === filename ? (
                                <CheckCircle2 className="w-4 h-4 text-green-400" />
                              ) : (
                                <Copy className="w-4 h-4" />
                              )}
                            </button>
                            <a
                              href={data.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-2 hover:bg-clawd-900 rounded transition-colors"
                              title="Download file"
                            >
                              <Download className="w-4 h-4" />
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Verification Instructions */}
            <div className="bg-clawd-800 rounded-lg p-6">
              <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
                <Shield className="w-6 h-6 text-clawd-accent" />
                Verification Instructions
              </h2>

              <p className="text-gray-300 mb-4">
                Always verify file integrity before using ClawSec files. Here's how:
              </p>

              <div className="space-y-4">
                <div>
                  <h3 className="font-semibold mb-2">1. Download a file</h3>
                  <CodeBlock
                    code={`curl -sL https://github.com/${checksums.repository}/releases/download/${checksums.version}/SKILL.md -o SKILL.md`}
                  />
                </div>

                <div>
                  <h3 className="font-semibold mb-2">2. Generate its checksum</h3>
                  <CodeBlock code="sha256sum SKILL.md" />
                </div>

                <div>
                  <h3 className="font-semibold mb-2">3. Compare with the checksum above</h3>
                  <p className="text-sm text-gray-400">
                    The output should exactly match the SHA256 value shown in the table.
                  </p>
                </div>

                <div className="mt-6 p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                  <p className="text-yellow-200 text-sm">
                    <strong>Security Warning:</strong> Never use files with mismatched checksums.
                    This could indicate tampering or a compromised download.
                  </p>
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="bg-clawd-800 rounded-lg p-12 text-center">
            <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">
              Checksums not available. Create a release to generate checksums.
            </p>
            <CodeBlock
              code={`# Create a release to generate checksums:\ngit tag v1.0.0 && git push origin v1.0.0`}
              className="mt-4 text-left"
            />
          </div>
        )}
      </div>
    </>
  );
}
