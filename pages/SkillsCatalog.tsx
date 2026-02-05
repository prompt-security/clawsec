import React, { useState, useEffect } from 'react';
import { Search as _Search, Filter as _Filter, Package, Sparkles, FileText, GitFork } from 'lucide-react';
import { SkillCard } from '../components/SkillCard';
import { Footer } from '../components/Footer';
import type { SkillMetadata, SkillsIndex } from '../types';

export const SkillsCatalog: React.FC = () => {
  const [skills, setSkills] = useState<SkillMetadata[]>([]);
  const [filteredSkills, setFilteredSkills] = useState<SkillMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, _setSearchTerm] = useState('');
  const [categoryFilter, _setCategoryFilter] = useState<string>('all');

  useEffect(() => {
    const fetchSkills = async () => {
      try {
        const response = await fetch('./skills/index.json');
        if (!response.ok) {
          throw new Error('Failed to fetch skills index');
        }
        const data: SkillsIndex = await response.json();
        setSkills(data.skills || []);
        setFilteredSkills(data.skills || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load skills');
      } finally {
        setLoading(false);
      }
    };

    fetchSkills();
  }, []);

  useEffect(() => {
    let result = skills;

    // Apply search filter
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(
        (skill) =>
          skill.name.toLowerCase().includes(term) ||
          skill.description.toLowerCase().includes(term)
      );
    }

    // Apply category filter
    if (categoryFilter !== 'all') {
      result = result.filter((skill) => skill.category === categoryFilter);
    }

    setFilteredSkills(result);
  }, [searchTerm, categoryFilter, skills]);

  // Get unique categories from skills (used in commented filter UI)
  const _categories = ['all', ...new Set(skills.map((s) => s.category).filter(Boolean))];

  if (loading) {
    return (
      <div className="pt-[52px]">
        <div className="py-16 text-center">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-clawd-accent"></div>
          <p className="mt-4 text-gray-400">Loading skills...</p>
        </div>
        <Footer />
      </div>
    );
  }

  if (error) {
    return (
      <div className="pt-[52px]">
        <div className="py-16 text-center">
          <Package className="w-16 h-16 mx-auto text-gray-600 mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">No Skills Available</h2>
          <p className="text-gray-400 mb-4">{error}</p>
          <p className="text-sm text-gray-500">
            Skills will appear here after the first skill release.
          </p>
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div className="pt-[52px] space-y-8">
      {/* Header */}
      <section className="text-center space-y-4">
        <h1 className="text-3xl md:text-4xl text-white">
          Skills Catalog
        </h1>
        <p className="text-gray-400 max-w-2xl mx-auto">
          Browse security skills for your AI agents. Each skill is verified for safety
          and distributed with checksums for integrity verification.
        </p>
      </section>

      {/* Filters - Hidden for now, uncomment when needed
      <section className="flex flex-col md:flex-row gap-4 max-w-4xl mx-auto">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={20} />
          <input
            type="text"
            placeholder="Search skills..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-clawd-800 border border-clawd-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-clawd-accent"
          />
        </div>

        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={20} />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="pl-10 pr-8 py-2.5 bg-clawd-800 border border-clawd-700 rounded-lg text-white appearance-none focus:outline-none focus:border-clawd-accent"
          >
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat === 'all' ? 'All Categories' : cat}
              </option>
            ))}
          </select>
        </div>
      </section>
      */}

      {/* Skills Grid */}
      {filteredSkills.length > 0 ? (
        <section className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredSkills.map((skill) => (
            <SkillCard key={skill.id} skill={skill} />
          ))}
        </section>
      ) : (
        <section className="text-center py-12">
          <Package className="w-12 h-12 mx-auto text-gray-600 mb-4" />
          <h3 className="text-lg font-medium text-white mb-2">No skills found</h3>
          <p className="text-gray-400">
            {searchTerm || categoryFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'No skills have been released yet'}
          </p>
        </section>
      )}

      {/* Stats */}
      {skills.length > 0 && (
        <section className="text-center text-sm text-gray-500">
          Showing {filteredSkills.length} of {skills.length} skills
        </section>
      )}

      {/* Shoutout */}
      <section className="max-w-4xl mx-auto">
        <div className="bg-clawd-900 border border-clawd-700 rounded-xl overflow-hidden">
          <div className="bg-clawd-800 px-6 py-4 border-b border-clawd-700 flex items-center justify-between">
            <h2 className="font-bold text-white flex items-center gap-2">
              <Sparkles size={18} className="text-clawd-accent" />
              Contribute Security Skills
            </h2>
            <span className="text-xs font-mono text-gray-500">SKILLS-BASED</span>
          </div>
          <div className="p-6 space-y-6">
            <p className="text-gray-300 text-sm">
              Humans & agents: submit skills that make bots safer (prompt injection defenses, drift checks, tool hardening, policy enforcement).
              We’ll package them with checksums so everyone can verify integrity.
            </p>

            <a
              href="https://github.com/prompt-security/clawsec/blob/main/CONTRIBUTING.md"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-start gap-4 p-4 rounded-lg bg-clawd-800/50 border border-clawd-700 hover:border-clawd-accent/50 transition-colors group"
            >
              <span className="text-2xl">📄</span>
              <div className="flex-1">
                <h4 className="text-white font-bold text-sm group-hover:text-clawd-accent transition-colors flex items-center gap-2">
                  Read CONTRIBUTING.md
                  <FileText size={14} className="text-gray-500" />
                </h4>
                <p className="text-xs text-gray-400 mt-1">
                  Guidelines for authoring, packaging, and releasing skills to the ClawSec catalog.
                </p>
              </div>
            </a>

            <a
              href="https://github.com/prompt-security/clawsec/fork"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-start gap-4 p-4 rounded-lg bg-clawd-800/50 border border-clawd-700 hover:border-clawd-accent/50 transition-colors group"
            >
              <span className="text-2xl">🍴</span>
              <div className="flex-1">
                <h4 className="text-white font-bold text-sm group-hover:text-clawd-accent transition-colors flex items-center gap-2">
                  Fork the repository
                  <GitFork size={14} className="text-gray-500" />
                </h4>
                <p className="text-xs text-gray-400 mt-1">
                  Start a contribution branch and open a PR with your new security skill.
                </p>
              </div>
            </a>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
};
