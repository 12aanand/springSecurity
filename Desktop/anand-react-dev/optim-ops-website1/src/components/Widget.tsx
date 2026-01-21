import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface Widget {
  title: string;
  value: string;
  change: string;
  trend: 'up' | 'down';
  icon: React.ReactNode;
  color: string;
  gradient: string;
}

interface WidgetProps {
  widget: Widget;
}

const Widget: React.FC<WidgetProps> = ({ widget }) => {
  const isPositive = widget.trend === 'up';

  return (
    <div className="group bg-white/80 backdrop-blur-xl rounded-3xl shadow-lg hover:shadow-xl border border-white/30 hover:border-white/50 transition-all duration-500 overflow-hidden">
      {/* Gradient Overlay */}
      <div className={`absolute inset-0 bg-gradient-to-br ${widget.gradient} opacity-0 group-hover:opacity-5 transition-opacity duration-500`}></div>
      
      <div className="relative p-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className={`w-14 h-14 bg-gradient-to-br ${widget.gradient} rounded-2xl flex items-center justify-center shadow-lg group-hover:shadow-xl transform group-hover:scale-110 transition-all duration-500`}>
            {widget.icon}
          </div>
          <div className={`flex items-center space-x-1 px-3 py-1 rounded-full text-xs font-semibold ${
            isPositive ? 'bg-green-100/80 text-green-700' : 'bg-red-100/80 text-red-700'
          } backdrop-blur-sm`}>
            {isPositive ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            <span>{widget.change}</span>
          </div>
        </div>

        {/* Content */}
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-gray-700 group-hover:text-gray-800 transition-colors duration-300 mb-2">
            {widget.title}
          </h3>
          <div className="text-4xl font-bold bg-gradient-to-r from-gray-800 via-blue-700 to-purple-700 bg-clip-text text-transparent group-hover:from-gray-900 group-hover:via-blue-800 group-hover:to-purple-800 transition-all duration-300">
            {widget.value}
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-gray-200/50 rounded-full h-2 mb-4 overflow-hidden">
          <div 
            className={`h-full bg-gradient-to-r ${widget.gradient} rounded-full transition-all duration-1000 group-hover:shadow-lg`}
            style={{ width: `${Math.random() * 60 + 40}%` }}
          ></div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between text-sm text-gray-600 group-hover:text-gray-700 transition-colors duration-300">
          <span>vs last month</span>
          <button 
            onClick={() => alert(`Viewing details for ${widget.title}`)}
            className={`px-4 py-2 bg-gradient-to-r ${widget.gradient} text-white rounded-xl text-xs font-medium shadow-md hover:shadow-lg transform hover:scale-105 transition-all duration-300 opacity-0 group-hover:opacity-100`}
          >
            View Details
          </button>
        </div>
      </div>

      {/* Decorative Elements */}
      <div className="absolute top-4 right-4 w-20 h-20 bg-gradient-to-br from-white/10 to-white/5 rounded-full blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
      <div className="absolute bottom-4 left-4 w-12 h-12 bg-gradient-to-tr from-white/5 to-white/10 rounded-full blur-lg opacity-0 group-hover:opacity-100 transition-opacity duration-700"></div>
    </div>
  );
};

export default Widget;