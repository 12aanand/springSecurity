import React from 'react';
import { Domain } from '../types/Domain';
import { Zap, Home } from 'lucide-react';

interface SidebarProps {
  domains: Domain[];
  selectedDomain: Domain;
  onDomainSelect: (domain: Domain) => void;
  onBackToHome: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ domains, selectedDomain, onDomainSelect, onBackToHome }) => {
  return (
    <div className="w-72 bg-gradient-to-b from-gray-900 via-blue-900 to-purple-900 text-white shadow-2xl flex flex-col">
      {/* Logo Section */}
      <div className="p-6 border-b border-gray-700/50">
        <div 
          onClick={onBackToHome}
          className="flex items-center space-x-3 cursor-pointer group hover:bg-white/10 rounded-2xl p-3 -m-3 transition-all duration-300"
        >
          <div className="w-10 h-10 bg-gradient-to-br from-blue-400 via-purple-400 to-indigo-500 rounded-xl flex items-center justify-center shadow-lg">
            <Zap className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold group-hover:text-blue-200 transition-colors duration-300">OPTIM OPS</h1>
            <p className="text-xs text-gray-400 group-hover:text-gray-300 transition-colors duration-300">Operations Platform</p>
          </div>
        </div>
      </div>

      {/* Home Button */}
      <div className="px-6 py-4">
        <button
          onClick={onBackToHome}
          className="w-full flex items-center space-x-3 px-4 py-3 bg-gradient-to-r from-blue-600/20 to-purple-600/20 hover:from-blue-500/30 hover:to-purple-500/30 rounded-2xl transition-all duration-300 group border border-blue-500/20 hover:border-blue-400/30"
        >
          <Home className="w-5 h-5 text-blue-300 group-hover:text-blue-200 transition-colors duration-300" />
          <span className="text-sm font-medium text-blue-100 group-hover:text-white transition-colors duration-300">Back to Home</span>
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-6 py-4">
        <div className="mb-4">
          <h3 className="text-xs uppercase text-gray-400 font-semibold tracking-wider mb-4">Industry Solutions</h3>
          <div className="space-y-2">
            {domains.map((domain) => {
              const IconComponent = domain.icon;
              const isSelected = selectedDomain.id === domain.id;
              
              return (
                <button
                  key={domain.id}
                  onClick={() => onDomainSelect(domain)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-2xl transition-all duration-300 group border ${
                    isSelected 
                      ? `bg-gradient-to-r ${domain.gradient} shadow-lg border-white/20` 
                      : 'hover:bg-white/10 border-transparent hover:border-white/10'
                  }`}
                >
                  <div className={`w-8 h-8 rounded-xl flex items-center justify-center transition-all duration-300 ${
                    isSelected 
                      ? 'bg-white/20 shadow-md' 
                      : 'bg-white/10 group-hover:bg-white/20'
                  }`}>
                    <IconComponent className={`w-4 h-4 transition-colors duration-300 ${
                      isSelected ? 'text-white' : 'text-gray-300 group-hover:text-white'
                    }`} />
                  </div>
                  <div className="flex-1 text-left">
                    <div className={`text-sm font-medium transition-colors duration-300 ${
                      isSelected ? 'text-white' : 'text-gray-300 group-hover:text-white'
                    }`}>
                      {domain.title}
                    </div>
                    <div className={`text-xs transition-colors duration-300 ${
                      isSelected ? 'text-white/80' : 'text-gray-500 group-hover:text-gray-300'
                    }`}>
                      {domain.subtitle}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </nav>

      {/* Footer */}
      <div className="p-6 border-t border-gray-700/50">
        <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 rounded-2xl p-4 border border-blue-500/20">
          <h4 className="text-sm font-semibold text-white mb-2">Need Help?</h4>
          <p className="text-xs text-gray-300 mb-3">Get support from our team</p>
          <button className="w-full py-2 px-4 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white rounded-xl text-xs font-medium shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300">
            Contact Support
          </button>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;