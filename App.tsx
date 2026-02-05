import React from 'react';
import { HashRouter as Router, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';
import { FeedSetup } from './pages/FeedSetup';
import { SkillsCatalog } from './pages/SkillsCatalog';
import { SkillDetail } from './pages/SkillDetail';
import { AdvisoryDetail } from './pages/AdvisoryDetail';

const App: React.FC = () => {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/skills" element={<SkillsCatalog />} />
          <Route path="/skills/:skillId" element={<SkillDetail />} />
          <Route path="/feed" element={<FeedSetup />} />
          <Route path="/feed/:advisoryId" element={<AdvisoryDetail />} />
        </Routes>
      </Layout>
    </Router>
  );
};

export default App;