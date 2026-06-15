import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Shield, Github } from 'lucide-react';
import Home from './Home';
import RepoDetail from './RepoDetail';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-900 text-gray-100 flex flex-col">
        {/* Header */}
        <header className="bg-gray-800 border-b border-gray-700 py-4 px-6 flex justify-between items-center sticky top-0 z-10 shadow-sm">
          <Link to="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
            <Shield className="w-8 h-8 text-green-500" />
            <span className="text-xl font-bold bg-gradient-to-r from-green-400 to-green-600 bg-clip-text text-transparent">
              PRobe
            </span>
          </Link>
          
          <div className="flex items-center gap-4">
            <a 
              href="https://github.com/apps/probe-security/installations/new" 
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-md text-sm font-medium transition-colors"
            >
              <Github className="w-4 h-4" />
              Install App
            </a>
          </div>
        </header>

        {/* Main Content */}
        <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/repo/:repoId" element={<RepoDetail />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
