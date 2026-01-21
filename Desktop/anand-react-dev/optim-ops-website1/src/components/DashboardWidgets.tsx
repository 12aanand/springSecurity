import React from 'react';
import Widget from './Widget';
import { getWidgetsForDomain } from '../utils/widgetUtils.tsx';
import { Domain } from '../types/Domain';

interface DashboardWidgetsProps {
  selectedDomain: Domain;
}

const DashboardWidgets: React.FC<DashboardWidgetsProps> = ({ selectedDomain }) => {
  const widgets = getWidgetsForDomain(selectedDomain.id);

  return (
    <div className="p-8 bg-gradient-to-br from-slate-50/50 via-blue-50/30 to-indigo-50/40">
      <div className="mb-8">
        <h2 className="text-3xl font-bold bg-gradient-to-r from-gray-800 via-blue-700 to-purple-700 bg-clip-text text-transparent mb-2">
          {selectedDomain.title} Dashboard
        </h2>
        <p className="text-gray-600 text-lg">
          Monitor and manage your {selectedDomain.subtitle.toLowerCase()} operations
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-8">
        {widgets.map((widget, index) => (
          <Widget key={index} widget={widget} />
        ))}
      </div>

      {/* Quick Actions */}
      <div className="mt-12">
        <h3 className="text-2xl font-bold bg-gradient-to-r from-gray-800 to-gray-900 bg-clip-text text-transparent mb-6">
          Quick Actions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {selectedDomain.features.map((feature, index) => (
            <button
              key={index}
              className={`p-6 bg-white/80 backdrop-blur-xl hover:bg-white/90 rounded-3xl shadow-lg hover:shadow-xl border border-white/30 hover:border-white/50 transition-all duration-300 text-left group transform hover:scale-105`}
            >
              <div className={`w-12 h-12 bg-gradient-to-br ${selectedDomain.gradient} rounded-2xl flex items-center justify-center mb-4 group-hover:shadow-lg transition-all duration-300`}>
                <div className="w-6 h-6 bg-white/20 rounded-lg"></div>
              </div>
              <h4 className="font-semibold text-gray-800 group-hover:text-gray-900 transition-colors duration-300">
                {feature}
              </h4>
              <p className="text-sm text-gray-600 mt-2 group-hover:text-gray-700 transition-colors duration-300">
                Access {feature.toLowerCase()} tools
              </p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DashboardWidgets;