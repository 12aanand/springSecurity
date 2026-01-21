import React from 'react';
import { Bell, Search, Settings, User } from 'lucide-react';
import { Domain } from '../types/Domain';

interface DashboardHeaderProps {
  selectedDomain: Domain;
}

const DashboardHeader: React.FC<DashboardHeaderProps> = ({ selectedDomain }) => {
  const IconComponent = selectedDomain.icon;

  return (
    <header className="bg-white/80 backdrop-blur-xl border-b border-gray-200/50 shadow-lg">
      <div className="px-8 py-4">
        <div className="flex items-center justify-between">
          {/* Left Section */}
          <div className="flex items-center space-x-4">
            <div className={`w-12 h-12 bg-gradient-to-br ${selectedDomain.gradient} rounded-2xl flex items-center justify-center shadow-lg`}>
              <IconComponent className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-gray-800 to-gray-900 bg-clip-text text-transparent">
                {selectedDomain.title}
              </h1>
              <p className="text-sm text-gray-600">{selectedDomain.subtitle}</p>
            </div>
          </div>

          {/* Right Section */}
          <div className="flex items-center space-x-4">
            {/* Search */}
            <div className="relative">
              <input
                type="text"
                placeholder="Search..."
                className="pl-10 pr-4 py-3 bg-gray-100/80 backdrop-blur-sm border border-gray-200/50 rounded-2xl focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500/50 transition-all duration-300 w-80"
              />
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
            </div>

            {/* Action Buttons */}
            <button className="w-12 h-12 bg-gradient-to-br from-gray-100/80 to-gray-200/60 backdrop-blur-sm hover:from-blue-100/80 hover:to-blue-200/60 rounded-2xl flex items-center justify-center shadow-md hover:shadow-lg transition-all duration-300 border border-gray-200/50 hover:border-blue-300/50 group">
              <Bell className="w-5 h-5 text-gray-600 group-hover:text-blue-600 transition-colors duration-300" />
            </button>

            <button className="w-12 h-12 bg-gradient-to-br from-gray-100/80 to-gray-200/60 backdrop-blur-sm hover:from-purple-100/80 hover:to-purple-200/60 rounded-2xl flex items-center justify-center shadow-md hover:shadow-lg transition-all duration-300 border border-gray-200/50 hover:border-purple-300/50 group">
              <Settings className="w-5 h-5 text-gray-600 group-hover:text-purple-600 transition-colors duration-300" />
            </button>

            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 via-purple-500 to-indigo-600 rounded-2xl flex items-center justify-center shadow-lg hover:shadow-xl cursor-pointer transform hover:scale-105 transition-all duration-300">
              <User className="w-5 h-5 text-white" />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

export default DashboardHeader;