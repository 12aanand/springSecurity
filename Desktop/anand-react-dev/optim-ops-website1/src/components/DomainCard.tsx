import React from 'react';
import { ArrowRight } from 'lucide-react';
import { Domain } from '../types/Domain';

interface DomainCardProps {
  domain: Domain;
  onClick: () => void;
  onExplore: () => void;
}

const DomainCard: React.FC<DomainCardProps> = ({ domain, onClick, onExplore }) => {
  const IconComponent = domain.icon;

  return (
    <div 
      className="group relative transform hover:scale-105 transition-all duration-500 ease-out"
    >
      <div className="relative bg-white/80 backdrop-blur-xl rounded-3xl shadow-xl hover:shadow-2xl border border-white/20 overflow-hidden transition-all duration-500 group-hover:border-white/40">
        {/* Gradient Overlay on Hover */}
        <div className={`absolute inset-0 bg-gradient-to-br ${domain.gradient} opacity-0 group-hover:opacity-10 transition-opacity duration-500`}></div>
        
        {/* Content */}
        <div className="relative p-8">
          {/* Icon Section */}
          <div className="flex items-center justify-center mb-6">
            <div className={`w-20 h-20 bg-gradient-to-br ${domain.gradient} rounded-2xl flex items-center justify-center shadow-lg group-hover:shadow-xl transform group-hover:scale-110 transition-all duration-500`}>
              <IconComponent className="w-10 h-10 text-white" />
            </div>
          </div>

          {/* Title */}
          <h3 className="text-2xl font-bold text-gray-900 mb-3 text-center group-hover:text-gray-800 transition-colors duration-300">
            {domain.title}
          </h3>

          {/* Description */}
          <p className="text-gray-600 text-center mb-6 leading-relaxed group-hover:text-gray-700 transition-colors duration-300">
            {domain.description}
          </p>

          {/* Features */}
          <div className="space-y-3 mb-8">
            {domain.features.map((feature, index) => (
              <div key={index} className="flex items-center space-x-3">
                <div className={`w-2 h-2 bg-gradient-to-r ${domain.gradient} rounded-full flex-shrink-0`}></div>
                <span className="text-sm text-gray-700 group-hover:text-gray-800 transition-colors duration-300">{feature}</span>
              </div>
            ))}
          </div>

          {/* Action Button */}
          <div className="space-y-3">
            <button 
              onClick={onExplore}
              className={`w-full py-4 px-6 bg-gradient-to-r ${domain.gradient} hover:shadow-xl text-white rounded-2xl font-semibold shadow-lg transform hover:scale-105 transition-all duration-300 flex items-center justify-center space-x-2 group-hover:shadow-2xl`}
            >
              <span>Explore {domain.title.split(' ')[2]}</span>
              <ArrowRight className="w-4 h-4 transform group-hover:translate-x-1 transition-transform duration-300" />
            </button>
            <button 
              onClick={onClick}
              className="w-full py-3 px-6 bg-white/80 hover:bg-white/90 text-gray-800 rounded-2xl font-medium shadow-md hover:shadow-lg transform hover:scale-105 transition-all duration-300 border border-gray-200/50 hover:border-gray-300/50"
            >
              Quick Demo
            </button>
          </div>
        </div>

        {/* Decorative Elements */}
        <div className="absolute top-4 right-4 w-24 h-24 bg-gradient-to-br from-white/20 to-white/5 rounded-full blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
        <div className="absolute bottom-4 left-4 w-16 h-16 bg-gradient-to-tr from-white/10 to-white/5 rounded-full blur-lg opacity-0 group-hover:opacity-100 transition-opacity duration-700"></div>
      </div>
    </div>
  );
};

export default DomainCard;