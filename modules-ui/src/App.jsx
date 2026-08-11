import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { SearchProvider } from './shared/context/SearchContext';
import BreachData from './modules/breach/BreachData';
import OSINTTools from './modules/osint/OSINTTools';
import ImageIntelligence from './modules/image-intelligence/ImageIntelligence';

function App() {
  const baseName = import.meta.env.BASE_URL.replace(/\/$/, '');
  return (
    <Router basename={baseName || undefined}>
      <SearchProvider>
        <Routes>
          <Route path="/breach" element={<BreachData />} />
          <Route path="/osint" element={<OSINTTools />} />
          <Route path="/image-intel" element={<ImageIntelligence />} />
          <Route path="*" element={<Navigate to="/osint" replace />} />
        </Routes>
      </SearchProvider>
    </Router>
  );
}

export default App;
