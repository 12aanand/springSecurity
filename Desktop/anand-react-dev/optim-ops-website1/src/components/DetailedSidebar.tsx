import React from 'react';
import { Domain } from '../types/Domain';
import { User } from '../types/User';
import { 
  Zap, 
  Home, 
  Users, 
  Plus, 
  CheckSquare, 
  Workflow, 
  FileText, 
  BarChart3,
  UserPlus,
  Building2,
  PlusCircle,
  ListTodo
} from 'lucide-react';

interface DetailedSidebarProps {
  domains: Domain[];
  selectedDomain: Domain;
  user: User;
  onDomainSelect: (domain: Domain) => void;
  onBackToHome: () => void;
  onLogout: () => void;
}

const DetailedSidebar: React.FC<DetailedSidebarProps> = ({ 
  domains, 
  selectedDomain, 
  user,
  onDomainSelect, 
  onBackToHome,
  onLogout 
}) => {
  const menuItems = [
    {
      title: 'Leads',
      icon: Users,
      items: [
        { name: 'All Leads', icon: Users },
        { name: 'Create Lead', icon: UserPlus }
      ]
    },
    {
      title: 'Accounts',
      icon: Building2,
      items: [
        { name: 'All Accounts', icon: Building2 },
        { name: 'Create Account', icon: PlusCircle }
      ]
    },
    {
      title: 'Tasks',
      icon: CheckSquare,
      items: [
        { name: 'All Tasks', icon: ListTodo },
        { name: 'Create Task', icon: Plus }
      ]
    },
    {
      title: 'Workflow Management',
      icon: Workflow,
      items: []
    },
    {
      title: 'GST Filing',
      icon: FileText,
      items: []
    },
    {
      title: 'Reports',
      icon: BarChart3,
      items: []
    }
  ];

  return (
    <div className="w-80 bg-gradient-to-b from-gray-900 via-blue-900 to-purple-900 text-white shadow-2xl flex flex-col">
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

      {/* User Info */}
      <div className="px-6 py-4 border-b border-gray-700/50">
        <div className="flex items-center space-x-3 mb-3">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 via-purple-500 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg">
            <span className="text-sm font-bold text-white">{user.name.charAt(0)}</span>
          </div>
          <div>
            <p className="text-sm font-semibold text-white">{user.name}</p>
            <p className="text-xs text-gray-400">{user.role}</p>
          </div>
        </div>
        <button
          onClick={onLogout}
          className="text-xs text-gray-400 hover:text-white transition-colors duration-200"
        >
          Sign Out
        </button>
      </div>

      {/* Home Button */}
      <div className="px-6 py-4">
        <button
          onClick={onBackToHome}
          className="w-full flex items-center space-x-3 px-4 py-3 bg-gradient-to-r from-blue-600/20 to-purple-600/20 hover:from-blue-500/30 hover:to-purple-500/30 rounded-2xl transition-all duration-300 group border border-blue-500/20 hover:border-blue-400/30"
        >
          <Home className="w-5 h-5 text-blue-300 group-hover:text-blue-200 transition-colors duration-300" />
          <span className="text-sm font-medium text-blue-100 group-hover:text-white transition-colors duration-300">Dashboard Home</span>
        </button>
      </div>

      {/* Domain Navigation */}
      <div className="px-6 py-4 border-b border-gray-700/50">
        <h3 className="text-xs uppercase text-gray-400 font-semibold tracking-wider mb-4">Switch Domain</h3>
        <div className="space-y-2">
          {domains.filter(domain => user.assignedDomains.includes(domain.id)).map((domain) => {
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
                    {domain.title.split(' ')[2]}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Menu Items */}
      <nav className="flex-1 px-6 py-4 overflow-y-auto">
        <div className="space-y-6">
          {menuItems.map((section, index) => {
            const SectionIcon = section.icon;
            
            return (
              <div key={index}>
                <div className="flex items-center space-x-3 px-4 py-3 text-gray-300 hover:text-white transition-colors duration-300 cursor-pointer group">
                  <SectionIcon className="w-5 h-5 group-hover:text-blue-300 transition-colors duration-300" />
                  <span className="font-semibold text-sm">{section.title}</span>
                </div>
                
                {section.items.length > 0 && (
                  <div className="ml-4 space-y-1">
                    {section.items.map((item, itemIndex) => {
                      const ItemIcon = item.icon;
                      
                      return (
                        <button
                          key={itemIndex}
                          className="w-full flex items-center space-x-3 px-4 py-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-xl transition-all duration-300 group"
                        >
                          <ItemIcon className="w-4 h-4 group-hover:text-blue-300 transition-colors duration-300" />
                          <span className="text-sm">{item.name}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
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

export default DetailedSidebar;