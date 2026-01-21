import React, { useState } from 'react';
import { ArrowRight, Check, Star, Users, Shield, Zap, ArrowLeft } from 'lucide-react';
import { Domain } from '../types/Domain';
import { productFeatures } from '../data/productFeatures';
import { subscriptionPlans } from '../data/subscriptionPlans';
import { SubscriptionPlan } from '../types/Subscription';

interface ProductDetailsPageProps {
  domain: Domain;
  onBackToHome: () => void;
  onGetStarted: (domain: Domain, selectedPlan?: SubscriptionPlan) => void;
}

const ProductDetailsPage: React.FC<ProductDetailsPageProps> = ({ 
  domain, 
  onBackToHome, 
  onGetStarted 
}) => {
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlan | null>(null);
  const [showPricing, setShowPricing] = useState(false);
  
  const IconComponent = domain.icon;
  const features = productFeatures[domain.id] || [];

  const handleGetStarted = () => {
    if (selectedPlan) {
      onGetStarted(domain, selectedPlan);
    } else {
      setShowPricing(true);
    }
  };

  const handlePlanSelect = (plan: SubscriptionPlan) => {
    setSelectedPlan(plan);
    setShowPricing(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 relative overflow-hidden">
      {/* Background Elements */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-gradient-to-br from-blue-400/30 via-purple-400/20 to-pink-400/30 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-gradient-to-tr from-green-400/20 via-blue-400/30 to-purple-400/20 rounded-full blur-3xl animate-pulse delay-1000"></div>
      </div>

      {/* Header */}
      <header className="relative z-10 backdrop-blur-sm bg-white/70 border-b border-white/20 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button
                onClick={onBackToHome}
                className="flex items-center space-x-2 px-4 py-2 text-gray-600 hover:text-gray-800 font-medium transition-colors duration-300 rounded-xl hover:bg-white/50"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back to Home</span>
              </button>
              <div className="flex items-center space-x-3">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-600 via-purple-600 to-indigo-700 rounded-xl flex items-center justify-center shadow-lg">
                  <Zap className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-700 bg-clip-text text-transparent">
                    OPTIM OPS
                  </h1>
                  <p className="text-sm text-gray-600 font-medium">One Platform. Infinite Possibilities.</p>
                </div>
              </div>
            </div>
            <button 
              onClick={handleGetStarted}
              className="px-8 py-3 bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-700 hover:from-blue-700 hover:via-purple-700 hover:to-indigo-800 text-white rounded-2xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 flex items-center space-x-2"
            >
              <span>Get Started</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Hero Section */}
        <div className="text-center mb-16">
          <div className={`w-24 h-24 bg-gradient-to-br ${domain.gradient} rounded-3xl flex items-center justify-center mx-auto mb-6 shadow-2xl`}>
            <IconComponent className="w-12 h-12 text-white" />
          </div>
          <h1 className="text-5xl font-bold bg-gradient-to-r from-gray-900 via-blue-800 to-purple-800 bg-clip-text text-transparent mb-4">
            {domain.title}
          </h1>
          <p className="text-xl text-gray-600 max-w-3xl mx-auto mb-8">
            {domain.description}
          </p>
          
          {selectedPlan && (
            <div className="inline-flex items-center space-x-2 px-6 py-3 bg-gradient-to-r from-green-100/80 to-emerald-100/80 backdrop-blur-sm rounded-2xl border border-green-200/50">
              <Check className="w-5 h-5 text-green-600" />
              <span className="text-green-800 font-semibold">
                {selectedPlan.name} Plan Selected - ${selectedPlan.price}/{selectedPlan.period}
              </span>
            </div>
          )}
        </div>

        {/* Features Section */}
        <div className="mb-16">
          <h2 className="text-4xl font-bold text-center bg-gradient-to-r from-gray-900 via-blue-800 to-purple-800 bg-clip-text text-transparent mb-12">
            Powerful Features & Real-World Applications
          </h2>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {features.map((feature, index) => (
              <div key={index} className="group bg-white/80 backdrop-blur-xl rounded-3xl shadow-xl hover:shadow-2xl border border-white/20 overflow-hidden transition-all duration-500 hover:border-white/40">
                <div className={`absolute inset-0 bg-gradient-to-br ${domain.gradient} opacity-0 group-hover:opacity-5 transition-opacity duration-500`}></div>
                
                <div className="relative p-8">
                  <div className="flex items-start justify-between mb-4">
                    <h3 className="text-2xl font-bold text-gray-900 group-hover:text-gray-800 transition-colors duration-300">
                      {feature.title}
                    </h3>
                    <div className={`px-3 py-1 rounded-full text-xs font-semibold ${
                      feature.planRequired === 'basic' ? 'bg-blue-100 text-blue-700' :
                      feature.planRequired === 'standard' ? 'bg-purple-100 text-purple-700' :
                      'bg-gradient-to-r from-orange-100 to-red-100 text-red-700'
                    }`}>
                      {feature.planRequired.toUpperCase()}
                    </div>
                  </div>
                  
                  <p className="text-gray-600 mb-6 leading-relaxed group-hover:text-gray-700 transition-colors duration-300">
                    {feature.description}
                  </p>
                  
                  <div className="bg-gradient-to-r from-gray-50/80 to-blue-50/60 backdrop-blur-sm rounded-2xl p-6 border border-gray-200/30">
                    <h4 className="font-semibold text-gray-800 mb-2 flex items-center">
                      <Star className="w-4 h-4 text-yellow-500 mr-2" />
                      Real-World Example
                    </h4>
                    <p className="text-gray-700 text-sm italic">
                      {feature.example}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Pricing Section */}
        <div className="mb-16">
          <div className="text-center mb-12">
            <h2 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-800 to-purple-800 bg-clip-text text-transparent mb-4">
              Choose Your Plan
            </h2>
            <p className="text-xl text-gray-600 max-w-2xl mx-auto">
              Select the perfect plan for your business needs and unlock the full potential of {domain.title}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {subscriptionPlans.map((plan) => (
              <div 
                key={plan.id}
                className={`relative bg-white/80 backdrop-blur-xl rounded-3xl shadow-xl border transition-all duration-500 overflow-hidden group cursor-pointer ${
                  plan.popular 
                    ? 'border-purple-300/50 shadow-2xl scale-105' 
                    : 'border-white/20 hover:border-white/40 hover:shadow-2xl hover:scale-105'
                } ${
                  selectedPlan?.id === plan.id ? 'ring-4 ring-blue-500/20 border-blue-400/50' : ''
                }`}
                onClick={() => handlePlanSelect(plan)}
              >
                {plan.popular && (
                  <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                    <div className="bg-gradient-to-r from-purple-500 via-pink-500 to-red-500 text-white px-6 py-2 rounded-full text-sm font-semibold shadow-lg">
                      Most Popular
                    </div>
                  </div>
                )}

                <div className={`absolute inset-0 bg-gradient-to-br ${domain.gradient} opacity-0 group-hover:opacity-5 transition-opacity duration-500`}></div>
                
                <div className="relative p-8">
                  <div className="text-center mb-8">
                    <h3 className="text-2xl font-bold text-gray-900 mb-2">{plan.name}</h3>
                    <p className="text-gray-600 mb-4">{plan.description}</p>
                    <div className="flex items-baseline justify-center">
                      <span className="text-5xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                        ${plan.price}
                      </span>
                      <span className="text-gray-500 ml-2">/{plan.period}</span>
                    </div>
                  </div>

                  <div className="space-y-4 mb-8">
                    {plan.features.map((feature, index) => (
                      <div key={index} className="flex items-center space-x-3">
                        <div className={`w-5 h-5 bg-gradient-to-r ${domain.gradient} rounded-full flex items-center justify-center flex-shrink-0`}>
                          <Check className="w-3 h-3 text-white" />
                        </div>
                        <span className="text-gray-700">{feature}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handlePlanSelect(plan);
                    }}
                    className={`w-full py-4 px-6 rounded-2xl font-semibold shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 ${
                      selectedPlan?.id === plan.id
                        ? `bg-gradient-to-r ${domain.gradient} text-white`
                        : plan.popular
                        ? `bg-gradient-to-r ${domain.gradient} text-white`
                        : 'bg-gray-100 text-gray-800 hover:bg-gray-200'
                    }`}
                  >
                    {selectedPlan?.id === plan.id ? 'Selected' : 'Select Plan'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* CTA Section */}
        <div className="text-center">
          <div className="bg-gradient-to-r from-white/90 via-white/70 to-white/50 backdrop-blur-xl rounded-3xl shadow-2xl border border-white/20 p-12 max-w-4xl mx-auto">
            <div className={`absolute inset-0 bg-gradient-to-br ${domain.gradient} opacity-5 rounded-3xl`}></div>
            
            <div className="relative">
              <h2 className="text-4xl font-bold bg-gradient-to-r from-gray-900 via-blue-800 to-purple-800 bg-clip-text text-transparent mb-4">
                Ready to Transform Your {domain.subtitle}?
              </h2>
              <p className="text-xl text-gray-600 mb-8 max-w-2xl mx-auto">
                Join thousands of businesses already using OPTIM OPS to streamline their operations and boost productivity.
              </p>
              
              <div className="flex items-center justify-center space-x-8 mb-8">
                <div className="flex items-center space-x-2">
                  <Users className="w-6 h-6 text-blue-600" />
                  <span className="text-gray-700 font-semibold">10,000+ Users</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Shield className="w-6 h-6 text-green-600" />
                  <span className="text-gray-700 font-semibold">Enterprise Security</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Star className="w-6 h-6 text-yellow-500" />
                  <span className="text-gray-700 font-semibold">4.9/5 Rating</span>
                </div>
              </div>

              <button
                onClick={handleGetStarted}
                className={`px-12 py-4 bg-gradient-to-r ${domain.gradient} hover:shadow-2xl text-white rounded-2xl font-bold text-lg shadow-xl transform hover:scale-105 transition-all duration-300 flex items-center space-x-3 mx-auto`}
              >
                <span>
                  {selectedPlan ? `Start with ${selectedPlan.name} Plan` : 'Choose Your Plan & Get Started'}
                </span>
                <ArrowRight className="w-5 h-5" />
              </button>

              {!selectedPlan && (
                <p className="text-sm text-gray-500 mt-4">
                  Select a plan above to get started with your free trial
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProductDetailsPage;